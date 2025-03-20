import * as fs from 'fs/promises';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Octokit } from '@octokit/rest';

const execPromise = promisify(exec);

const LARGE_BUFFER = 1024 * 1024 * 100;

interface NpmAuditResult {
  vulnerabilities: Record<string, { name: string; severity: string; via: any[]; range: string; fixAvailable?: any }>;
}

interface Vulnerability {
  id: string;
  description: string;
  affectedVersion: string;
  fixedVersion?: string;
}

interface VulnerabilityReport {
  repoName: string;
  fixedCount: number;
  fixed: string[];
  unresolvedCount: number;
  unresolved: string[];
  prLink?: string;
}

class VulnerabilityFixer {
  private config: { reposDir: string };
  private report: VulnerabilityReport[] = [];
  private concurrencyLimit = 10;

  constructor(config: { reposDir: string }) {
    this.config = config;
  }

  async fixAllRepositories(): Promise<void> {
    try {
      await this.verifyNpmInstallation();
      const packageJsonPaths = await this.findPackageJsonFiles(this.config.reposDir);
      console.log(`Found ${packageJsonPaths.length} package.json files to scan`);

      // Process repositories concurrently with a limit
      for (let i = 0; i < packageJsonPaths.length; i += this.concurrencyLimit) {
        const chunk = packageJsonPaths.slice(i, i + this.concurrencyLimit);
        await Promise.all(chunk.map(packageJsonPath => this.processRepository(path.dirname(packageJsonPath))));
      }

      const date = new Date().toISOString().split('T')[0];
      const reportPath = path.join(this.config.reposDir, `${date}.json`);
      await fs.writeFile(reportPath, JSON.stringify(this.report, null, 2));
      console.log('Fixing complete. Report saved locally at:', reportPath);
    } catch (error) {
      console.error('Error fixing repositories:', error.message);
    }
  }

  private async verifyNpmInstallation(): Promise<void> {
    try {
      const { stdout } = await execPromise('npm -v');
      console.log(`npm version: ${stdout.trim()}`);
    } catch (error) {
      throw new Error(`npm is not installed or not accessible: ${error.message}`);
    }
  }

  private async findPackageJsonFiles(dir: string): Promise<string[]> {
    const packageJsonPaths: string[] = [];
    const dirents = await fs.readdir(dir, { withFileTypes: true });

    for (const dirent of dirents) {
      const fullPath = path.join(dir, dirent.name);
      if (dirent.isDirectory() && dirent.name !== 'node_modules') {
        packageJsonPaths.push(...await this.findPackageJsonFiles(fullPath));
      } else if (dirent.name === 'package.json') {
        packageJsonPaths.push(fullPath);
      }
    }
    return packageJsonPaths;
  }

  private async processRepository(repoPath: string): Promise<void> {
    const repoName = path.basename(repoPath);
    const repoReport: VulnerabilityReport = { repoName, fixedCount: 0, fixed: [], unresolvedCount: 0, unresolved: [] };
    let currentBranch: string | undefined;
    let hadStash = false;

    try {
      console.log(`\n--- Processing repository: ${repoPath} ---`);

      await fs.access(path.join(repoPath, 'package.json'), fs.constants.R_OK);
      await execPromise('git rev-parse --is-inside-work-tree', { cwd: repoPath });

      currentBranch = (await execPromise('git branch --show-current', { cwd: repoPath })).stdout.trim();
      if (currentBranch !== 'dev') {
        const { stdout: status } = await execPromise('git status --porcelain', { cwd: repoPath });
        if (status) {
          console.log(`Stashing changes in ${repoPath}`);
          await execPromise('git stash push -m "auto-stash-before-vuln-fix" --quiet', { cwd: repoPath });
          hadStash = true;
        }
        console.log(`Checking out dev in ${repoPath}`);
        await execPromise('git checkout dev --quiet', { cwd: repoPath });
        console.log(`Pulling dev in ${repoPath}`);
        await execPromise('git pull origin dev --quiet', { cwd: repoPath });
      }

      const branchName = `fix/vuls-${repoName}-${Date.now()}`;
      console.log(`Creating branch ${branchName} in ${repoPath}`);
      await execPromise(`git checkout -b ${branchName} --quiet`, { cwd: repoPath });

      await this.ensureDependenciesInstalled(repoPath);
      const vulnerabilities = await this.detectDependencyVulnerabilities(repoPath, repoReport);

      if (vulnerabilities.length > 0) {
        await this.applyFixes(repoPath, repoReport, vulnerabilities);
        const prLink = await this.commitAndPushChanges(repoPath, branchName, repoName);
        repoReport.prLink = prLink;
      } else {
        console.log(`No vulnerabilities found in ${repoPath}`);
        await execPromise(`git checkout ${currentBranch} --quiet`, { cwd: repoPath });
        await execPromise(`git branch -d ${branchName} --quiet`, { cwd: repoPath });
      }

      // Update counts in the report
      repoReport.fixedCount = repoReport.fixed.length;
      repoReport.unresolvedCount = repoReport.unresolved.length;
    } catch (error) {
      console.error(`Error processing ${repoPath}:`, error.message);
      repoReport.unresolved.push(`Processing failed - ${error.message}`);
      repoReport.unresolvedCount = repoReport.unresolved.length;
    } finally {
      if (currentBranch) {
        try {
          console.log(`Restoring branch ${currentBranch} in ${repoPath}`);
          await execPromise(`git checkout ${currentBranch} --quiet`, { cwd: repoPath });
          if (hadStash) {
            console.log(`Popping stash in ${repoPath}`);
            await execPromise('git stash pop --quiet', { cwd: repoPath });
          }
        } catch (cleanupError) {
          console.error(`Failed to cleanup ${repoPath}:`, cleanupError.message);
          repoReport.unresolved.push(`Cleanup failed - ${cleanupError.message}`);
          repoReport.unresolvedCount = repoReport.unresolved.length;
        }
      }
      this.report.push(repoReport);
      console.log(`--- Finished processing ${repoPath} ---`);
    }
  }

  private async ensureDependenciesInstalled(repoPath: string): Promise<void> {
    const nodeModulesPath = path.join(repoPath, 'node_modules');
    const lockFilePath = path.join(repoPath, 'package-lock.json');
    try {
      const hasNodeModules = await fs.stat(nodeModulesPath).catch(() => false);
      const hasLockFile = await fs.stat(lockFilePath).catch(() => false);

      if (!hasNodeModules || !hasLockFile) {
        console.log(`Installing dependencies in ${repoPath}`);
        await execPromise('npm install', { cwd: repoPath });
      }
    } catch (error) {
      throw new Error(`Failed to ensure dependencies in ${repoPath}: ${error.message}`);
    }
  }

  private async detectDependencyVulnerabilities(repoPath: string, repoReport: VulnerabilityReport): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    try {
      console.log(`Running npm audit in ${repoPath}`);
      const { stdout, stderr } = await execPromise('npm audit --json', { cwd: repoPath, maxBuffer: LARGE_BUFFER });

      if (stderr) console.warn(`npm audit warning: ${stderr}`);

      const auditResult: NpmAuditResult = JSON.parse(stdout);
      const vulnCount = Object.keys(auditResult.vulnerabilities || {}).length;
      console.log(`Found ${vulnCount} vulnerabilities in ${repoPath}`);

      for (const [depName, vuln] of Object.entries(auditResult.vulnerabilities || {})) {
        const fixedVersion = typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable?.version : undefined;

        vulnerabilities.push({
          id: `DEP-${depName}-${vuln.via[0]?.cve || depName}`,
          description: vuln.via[0]?.title || 'Dependency vulnerability',
          affectedVersion: vuln.range,
          fixedVersion
        });
      }
    } catch (error: any) {
      if (error.code === 1 && error.stdout) {
        console.log(`Audit completed with vulnerabilities (exit code 1) in ${repoPath}`);
        try {
          const auditResult: NpmAuditResult = JSON.parse(error.stdout);
          const vulnCount = Object.keys(auditResult.vulnerabilities || {}).length;
          console.log(`Found ${vulnCount} vulnerabilities in ${repoPath}`);

          for (const [depName, vuln] of Object.entries(auditResult.vulnerabilities || {})) {
            const fixedVersion = typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable?.version : undefined;

            vulnerabilities.push({
              id: `DEP-${depName}-${vuln.via[0]?.cve || depName}`,
              description: vuln.via[0]?.title || 'Dependency vulnerability',
              affectedVersion: vuln.range,
              fixedVersion
            });
          }
        } catch (parseError) {
          console.error(`Failed to parse audit output in ${repoPath}:`, parseError.message);
          repoReport.unresolved.push(`Audit output parsing failed - ${parseError.message}`);
        }
      } else {
        console.error(`Audit failed in ${repoPath}:`, error.message);
        repoReport.unresolved.push(`Audit failed - ${error.message}`);
      }
    }
    return vulnerabilities;
  }

  private async applyFixes(repoPath: string, repoReport: VulnerabilityReport, vulnerabilities: Vulnerability[]): Promise<void> {
    try {
      const preVulnIds = new Set(vulnerabilities.map(v => v.id));

      console.log(`Applying fixes in ${repoPath}`);
      await execPromise('npm audit fix', { cwd: repoPath });

      const postVulnerabilities = await this.detectDependencyVulnerabilities(repoPath, repoReport);
      const postVulnIds = new Set(postVulnerabilities.map(v => v.id));

      preVulnIds.forEach(vulnId => {
        if (!postVulnIds.has(vulnId)) {
          repoReport.fixed.push(vulnId);
        } else {
          repoReport.unresolved.push(vulnId);
        }
      });
    } catch (error) {
      console.error(`Fix application failed in ${repoPath}:`, error.message);
      repoReport.unresolved.push(`Fix application failed - ${error.message}`);
    }
  }

  private async commitAndPushChanges(repoPath: string, branchName: string, repoName: string): Promise<string | undefined> {
    const octokit = new Octokit({
      auth: ' ADD GH TOKEN HERE ', // Replace with your token
    });

    try {
      console.log(`Staging package.json and package-lock.json in ${repoPath}`);
      await execPromise('git add package.json package-lock.json', { cwd: repoPath });

      console.log(`Checking for changes in ${repoPath}`);
      const { stdout: status } = await execPromise('git status --porcelain', { cwd: repoPath, maxBuffer: LARGE_BUFFER });
      if (!status) {
        console.log(`No changes detected after fixes in ${repoPath}`);
        await execPromise(`git checkout dev --quiet`, { cwd: repoPath });
        await execPromise(`git branch -d ${branchName} --quiet`, { cwd: repoPath });
        return undefined;
      }

      console.log(`Adding all changes in ${repoPath}`);
      await execPromise('git add .', { cwd: repoPath });

      console.log(`Committing changes in ${repoPath}`);
      await execPromise('git commit -m "Automated vulnerability fixes" --quiet', { cwd: repoPath });

      console.log(`Pushing changes to ${branchName} in ${repoPath}`);
      await execPromise(`git push origin ${branchName} --quiet`, { cwd: repoPath, maxBuffer: LARGE_BUFFER });

      console.log(`Fetching remote URL for ${repoPath}`);
      const { stdout: remoteUrl } = await execPromise('git remote get-url origin', { cwd: repoPath, maxBuffer: LARGE_BUFFER });
      const repoSlug = remoteUrl.trim().match(/github\.com[/:](.+?\/.+?)(\.git)?$/)?.[1];
      if (!repoSlug) {
        throw new Error('Could not determine repository slug from remote URL');
      }

      const [owner, repo] = repoSlug.split('/');

      console.log(`Creating PR for ${repoPath} via GitHub API`);
      const prResponse = await octokit.pulls.create({
        owner,
        repo,
        title: `Automated vulnerability fixes for ${repoName}`,
        body: 'Fixes vulnerabilities detected by npm audit',
        head: branchName,
        base: 'dev',
      });

      const prLink = prResponse.data.html_url;
      console.log(`PR created for ${repoPath}: ${prLink}`);
      return prLink;
    } catch (error) {
      console.error(`Failed to commit or push changes in ${repoPath}:`, error.message);
      throw error;
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const reposDir = args[0];

  if (!reposDir) {
    console.error('Error: Please provide the parent repository directory as a command-line argument.');
    console.error('Usage: node script.js <reposDir>');
    process.exit(1);
  }

  const fixer = new VulnerabilityFixer({ reposDir });
  await fixer.fixAllRepositories();
}

main().catch(console.error);