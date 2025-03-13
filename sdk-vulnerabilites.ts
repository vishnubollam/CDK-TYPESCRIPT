import * as fs from 'fs/promises';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  via: Array<{ cve?: string; title?: string }>;
  effects: string[];
  range: string;
  fixAvailable?: { name: string; version: string; isSemVerMajor?: boolean } | boolean;
}

interface NpmAuditResult {
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
  };
}

interface Vulnerability {
  id: string;
  fix: (repoPath: string) => Promise<string | null>;
  description?: string;
  affectedVersion?: string;
  fixedVersion?: string;
}

interface Config {
  reposDir: string;
  repoUrl?: string;
}

class VulnerabilityFixer {
  private config: Config;
  private report: { detected: string[]; fixed: string[]; unresolved: string[] } = {
    detected: [],
    fixed: [],
    unresolved: []
  };

  constructor(config: Config) {
    this.config = config;
  }

  async fixAllRepositories(): Promise<void> {
    try {
      await this.verifyNpmInstallation();
      
      if (this.config.repoUrl) {
        const repoName = this.config.repoUrl.split('/').pop()?.replace('.git', '') || 'repo';
        const repoPath = path.join(this.config.reposDir, repoName);
        await fs.mkdir(this.config.reposDir, { recursive: true });
        console.log(`Cloning ${this.config.repoUrl} into ${repoPath}`);
        await execPromise(`git clone ${this.config.repoUrl} ${repoName}`, { cwd: this.config.reposDir })
          .catch(error => console.log(`Clone failed, proceeding with existing: ${error.message}`));
        this.config.reposDir = repoPath;
      }

      const packageJsonPaths = await this.findPackageJsonFiles(this.config.reposDir);
      console.log(`Found ${packageJsonPaths.length} package.json files to scan:`, packageJsonPaths);
      await Promise.all(packageJsonPaths.map(packageJsonPath => this.processPackageJson(packageJsonPath)));
      console.log('Fixing complete. Report:', this.report);
      await fs.writeFile(
        path.join(this.config.reposDir, 'vulnerability-report.json'),
        JSON.stringify(this.report, null, 2)
      );
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

  private async processPackageJson(packageJsonPath: string): Promise<void> {
    const repoPath = path.dirname(packageJsonPath);
    console.log(`Processing package.json at: ${packageJsonPath}`);
    
    try {
      const packageJsonContent = await fs.readFile(packageJsonPath, 'utf-8');
      JSON.parse(packageJsonContent);

      await this.ensureDependenciesInstalled(repoPath);
      const vulnerabilities = await this.detectDependencyVulnerabilities(repoPath);
      this.report.detected.push(...vulnerabilities.map(v => `${repoPath}: ${v.id}`));
      
      if (vulnerabilities.length > 0) {
        await this.applyFixes(repoPath, vulnerabilities);
        await this.commitChanges(repoPath);
      } else {
        console.log(`No vulnerabilities found in ${repoPath}`);
      }
    } catch (error) {
      console.error(`Error processing ${repoPath}:`, error.message);
      this.report.unresolved.push(`${repoPath}: Processing failed - ${error.message}`);
    }
  }

  private async ensureDependenciesInstalled(repoPath: string): Promise<void> {
    try {
      const nodeModulesPath = path.join(repoPath, 'node_modules');
      if (!(await fs.stat(nodeModulesPath).catch(() => false))) {
        console.log(`No node_modules found. Installing dependencies in ${repoPath}`);
        await execPromise('npm install', { cwd: repoPath });
      }
    } catch (error) {
      console.error(`Failed to ensure dependencies in ${repoPath}:`, error.message);
      throw error;
    }
  }

  private async detectDependencyVulnerabilities(repoPath: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      console.log(`Running npm audit in ${repoPath}`);
      const { stdout, stderr } = await execPromise('npm audit --json', { cwd: repoPath, maxBuffer: 1024 * 1024 });
      
      if (stderr) {
        console.warn(`npm audit warning: ${stderr}`);
      }
      
      const auditResult: NpmAuditResult = JSON.parse(stdout);
      const vulnCount = Object.keys(auditResult.vulnerabilities || {}).length;
      console.log(`Found ${vulnCount} vulnerabilities in ${repoPath}`);
      
      for (const [depName, vuln] of Object.entries(auditResult.vulnerabilities || {})) {
        const fixedVersion = typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable?.version : undefined;
        
        if (vuln.fixAvailable) {
          vulnerabilities.push({
            id: `DEP-${depName}-${vuln.via[0]?.cve || depName}`,
            fix: async (repoPath: string) => {
              console.log(`Attempting to fix ${depName}${fixedVersion ? ` to ${fixedVersion}` : ''} in ${repoPath}`);
              const success = await this.fixDependency(repoPath, depName, fixedVersion);
              if (success) {
                this.report.fixed.push(`${repoPath}: ${depName}${fixedVersion ? ` updated to ${fixedVersion}` : ' fixed'}`);
                return repoPath;
              } else {
                this.report.unresolved.push(`${repoPath}: ${depName} update failed - manual review required`);
                return null;
              }
            },
            description: vuln.via[0]?.title || 'Dependency vulnerability',
            affectedVersion: vuln.range,
            fixedVersion
          });
        } else {
          this.report.unresolved.push(`${repoPath}: ${depName} - no automatic fix available`);
        }
      }
    } catch (error: any) {
      if (error.code === 1 && error.stdout) {
        // Handle case where audit "fails" due to vulnerabilities but provides output
        console.log('Audit completed with vulnerabilities (exit code 1)');
        const auditResult: NpmAuditResult = JSON.parse(error.stdout);
        const vulnCount = Object.keys(auditResult.vulnerabilities || {}).length;
        console.log(`Found ${vulnCount} vulnerabilities in ${repoPath}`);
        
        for (const [depName, vuln] of Object.entries(auditResult.vulnerabilities || {})) {
          const fixedVersion = typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable?.version : undefined;
          
          if (vuln.fixAvailable) {
            vulnerabilities.push({
              id: `DEP-${depName}-${vuln.via[0]?.cve || depName}`,
              fix: async (repoPath: string) => {
                console.log(`Attempting to fix ${depName}${fixedVersion ? ` to ${fixedVersion}` : ''} in ${repoPath}`);
                const success = await this.fixDependency(repoPath, depName, fixedVersion);
                if (success) {
                  this.report.fixed.push(`${repoPath}: ${depName}${fixedVersion ? ` updated to ${fixedVersion}` : ' fixed'}`);
                  return repoPath;
                } else {
                  this.report.unresolved.push(`${repoPath}: ${depName} update failed - manual review required`);
                  return null;
                }
              },
              description: vuln.via[0]?.title || 'Dependency vulnerability',
              affectedVersion: vuln.range,
              fixedVersion
            });
          } else {
            this.report.unresolved.push(`${repoPath}: ${depName} - no automatic fix available`);
          }
        }
      } else {
        console.error(`Audit failed in ${repoPath}:`, error.message);
        if (error.stderr) console.error(`Audit stderr: ${error.stderr}`);
        if (error.stdout) console.error(`Audit stdout: ${error.stdout}`);
        if (error.code) console.error(`Exit code: ${error.code}`);
        this.report.unresolved.push(`${repoPath}: Audit failed - ${error.message}`);
      }
    }
    return vulnerabilities;
  }

  private async fixDependency(repoPath: string, depName: string, fixedVersion?: string): Promise<boolean> {
    try {
      console.log(`Running npm audit fix for ${depName} in ${repoPath}`);
      const { stderr: fixStderr } = await execPromise('npm audit fix --force', { cwd: repoPath });
      if (fixStderr) console.warn(`npm audit fix warning: ${fixStderr}`);

      // Verifying fix
      const { stdout } = await execPromise('npm audit --json', { cwd: repoPath });
      const auditResult: NpmAuditResult = JSON.parse(stdout);
      
      if (!auditResult.vulnerabilities?.[depName]) {
        return true;
      }

      if (fixedVersion) {
        // Return it to manual update if audit fix didn't work
        console.log(`Falling back to manual update for ${depName} to ${fixedVersion}`);
        const packageJsonPath = path.join(repoPath, 'package.json');
        const content = await fs.readFile(packageJsonPath, 'utf-8');
        const packageJson = JSON.parse(content);

        if (packageJson.dependencies?.[depName] || packageJson.devDependencies?.[depName]) {
          const depType = packageJson.dependencies?.[depName] ? 'dependencies' : 'devDependencies';
          packageJson[depType][depName] = fixedVersion;
          
          await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));
          const { stderr: installStderr } = await execPromise('npm install', { cwd: repoPath });
          if (installStderr) console.warn(`npm install warning: ${installStderr}`);

          // Final verification
          const { stdout: finalAudit } = await execPromise('npm audit --json', { cwd: repoPath });
          const finalResult: NpmAuditResult = JSON.parse(finalAudit);
          return !finalResult.vulnerabilities?.[depName];
        }
      }
      return false;
    } catch (error) {
      console.error(`Error fixing ${depName} in ${repoPath}:`, error.message);
      return false;
    }
  }

  private async applyFixes(repoPath: string, vulnerabilities: Vulnerability[]): Promise<void> {
    for (const vuln of vulnerabilities) {
      await vuln.fix(repoPath);
    }
  }

  private async commitChanges(repoPath: string): Promise<void> {
    try {
      await execPromise('git add .', { cwd: repoPath });
      await execPromise(
        `git commit -m "Automated vulnerability fixes for ${path.basename(repoPath)}"`,
        { cwd: repoPath }
      );
      console.log(`Committed changes in ${repoPath}`);
    } catch (error) {
      console.log(`No changes to commit or error in ${repoPath}:`, error.message);
    }
  }
}

async function main() {
  const config: Config = {
    reposDir: 'path to clone the repository',
    repoUrl: 'URL of the Repository'
  };

  const fixer = new VulnerabilityFixer(config);
  await fixer.fixAllRepositories();
}

main().catch(console.error);