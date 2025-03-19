import * as fs from 'fs/promises';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

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
  fixed: string[];
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
    const repoReport: VulnerabilityReport = { repoName, fixed: [], unresolved: [] };
    let currentBranch: string | undefined;
    let hadStash = false;

    try {
      console.log(`Processing repository: ${repoPath}`);

      const packageJsonPath = path.join(repoPath, 'package.json');
      await fs.access(packageJsonPath, fs.constants.R_OK);

      currentBranch = (await execPromise('git branch --show-current', { cwd: repoPath })).stdout.trim();
      if (currentBranch !== 'main') {
        const { stdout: status } = await execPromise('git status --porcelain', { cwd: repoPath });
        if (status) {
          await execPromise('git stash push -m "auto-stash-before-vuln-fix"', { cwd: repoPath });
          hadStash = true;
        }
        await execPromise('git checkout main', { cwd: repoPath });
        await execPromise('git pull origin main', { cwd: repoPath });
      }

      const branchName = `fix/vuls-${repoName}-${Date.now()}`;
      await execPromise(`git checkout -b ${branchName}`, { cwd: repoPath });

      await this.ensureDependenciesInstalled(repoPath);
      const vulnerabilities = await this.detectDependencyVulnerabilities(repoPath, repoReport);

      if (vulnerabilities.length > 0) {
        await this.applyFixes(repoPath, repoReport, vulnerabilities);
        const prLink = await this.commitAndPushChanges(repoPath, branchName);
        repoReport.prLink = prLink;
      } else {
        console.log(`No vulnerabilities found in ${repoPath}`);
      }
    } catch (error) {
      console.error(`Error processing ${repoPath}:`, error.message);
      repoReport.unresolved.push(`Processing failed - ${error.message}`);
    } finally {
      if (currentBranch) {
        try {
          await execPromise(`git checkout ${currentBranch}`, { cwd: repoPath });
          if (hadStash) {
            await execPromise('git stash apply', { cwd: repoPath });
          }
        } catch (cleanupError) {
          console.error(`Failed to cleanup ${repoPath}:`, cleanupError.message);
          repoReport.unresolved.push(`Cleanup failed - ${cleanupError.message}`);
        }
      }
      this.report.push(repoReport);
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
      const { stdout, stderr } = await execPromise('npm audit --json', { cwd: repoPath, maxBuffer: 1024 * 1024 });

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
          repoReport.unresolved.push(`${repoPath}: Audit output parsing failed - ${parseError.message}`);
        }
      } else {
        console.error(`Audit failed in ${repoPath}:`, error.message);
        if (error.stderr) console.error(`Audit stderr: ${error.stderr}`);
        if (error.stdout) console.error(`Audit stdout: ${error.stdout}`);
        if (error.code) console.error(`Exit code: ${error.code}`);

        const lockFilePath = path.join(repoPath, 'package-lock.json');
        const hasLockFile = await fs.stat(lockFilePath).catch(() => false);
        if (!hasLockFile) {
          console.error(`No package-lock.json found in ${repoPath}. Attempting to generate...`);
          try {
            await execPromise('npm install', { cwd: repoPath });
            console.log(`Generated package-lock.json in ${repoPath}. Retrying audit...`);
            return this.detectDependencyVulnerabilities(repoPath, repoReport); // Retry
          } catch (installError) {
            console.error(`Failed to generate package-lock.json: ${installError.message}`);
            repoReport.unresolved.push(`${repoPath}: Failed to generate package-lock.json - ${installError.message}`);
          }
        }

        repoReport.unresolved.push(`${repoPath}: Audit failed - ${error.message}`);
      }
    }
    return vulnerabilities;
  }

  private async applyFixes(repoPath: string, repoReport: VulnerabilityReport, vulnerabilities: Vulnerability[]): Promise<void> {
    try {
      const preVulnIds = new Set(vulnerabilities.map(v => v.id));

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

  private async commitAndPushChanges(repoPath: string, branchName: string): Promise<string | undefined> {
    try {
      await execPromise('git add .', { cwd: repoPath });
      await execPromise('git commit -m "Automated vulnerability fixes"', { cwd: repoPath });
      await execPromise(`git push origin ${branchName}`, { cwd: repoPath });

      const { stdout } = await execPromise(
        `gh pr create --base main --title "Automated vulnerability fixes for ${path.basename(repoPath)}" --body "Fixes vulnerabilities detected by npm audit"`,
        { cwd: repoPath }
      );
      const prLink = stdout.trim();
      console.log(`PR created for ${repoPath}: ${prLink}`);
      return prLink;
    } catch (error) {
      console.log(`No changes to commit or push failed in ${repoPath}:`, error.message);
      return undefined;
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