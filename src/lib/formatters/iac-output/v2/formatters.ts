import { FormattedResult } from '../../../../cli/commands/test/iac/local-execution/types';
import { Results, Vulnerability } from '../../../iac/test/v2/scan/results';
import { SEVERITY } from '../../../snyk-test/legacy';
import { IacOutputMeta } from '../../../types';
import {
  FormattedOutputResultsBySeverity,
  IacTestCounts,
  IacTestData,
  Issue,
} from './types';

interface FormatTestDataParams {
  oldFormattedResults: FormattedResult[];
  iacOutputMeta: IacOutputMeta | undefined;
  ignoresCount: number;
}

export function formatTestData({
  oldFormattedResults,
  iacOutputMeta: iacTestMeta,
  ignoresCount,
}: FormatTestDataParams): IacTestData {
  const resultsBySeverity = formatScanResultsNewOutput(oldFormattedResults);

  return {
    resultsBySeverity,
    metadata: iacTestMeta,
    counts: formatTestCounts(resultsBySeverity, {
      oldFormattedResults,
      ignoresCount,
    }),
  };
}

function formatTestCounts(
  resultsBySeverity: FormattedOutputResultsBySeverity,
  {
    oldFormattedResults,
    ignoresCount,
  }: Pick<FormatTestDataParams, 'ignoresCount' | 'oldFormattedResults'>,
): IacTestCounts {
  const filesWithIssues = oldFormattedResults.filter(
    (result) => result.result.cloudConfigResults.length,
  ).length;

  const filesWithoutIssues = oldFormattedResults.length - filesWithIssues;

  let totalIssues = 0;

  const issuesCountBySeverity = {} as { [key in SEVERITY]: number };
  Object.values(SEVERITY).forEach((severity) => {
    issuesCountBySeverity[severity] = resultsBySeverity[severity]?.length || 0;
    totalIssues += issuesCountBySeverity[severity];
  });

  return {
    ignores: ignoresCount,
    filesWithIssues,
    filesWithoutIssues,
    issuesBySeverity: issuesCountBySeverity,
    issues: totalIssues,
  };
}

function formatScanResultsNewOutput(
  oldFormattedResults: FormattedResult[],
): FormattedOutputResultsBySeverity {
  const newFormattedResults: FormattedOutputResultsBySeverity = {};

  oldFormattedResults.forEach((oldFormattedResult) => {
    oldFormattedResult.result.cloudConfigResults.forEach((issue) => {
      if (!newFormattedResults[issue.severity]) {
        newFormattedResults[issue.severity] = [];
      }

      newFormattedResults[issue.severity].push({
        issue,
        targetFile: oldFormattedResult.targetFile,
        projectType: oldFormattedResult.result.projectType,
      });
    });
  });

  return newFormattedResults;
}

export function formatSnykIacTestTestData(
  snykIacTestScanResult: Results | undefined,
  projectName: string,
  orgName: string,
): IacTestData {
  const resultsBySeverity = formatSnykIacTestScanResultNewOutput(
    snykIacTestScanResult,
  );

  let totalIssues = 0;

  const issuesCountBySeverity = {} as { [key in SEVERITY]: number };
  Object.values(SEVERITY).forEach((severity) => {
    issuesCountBySeverity[severity] = resultsBySeverity[severity]?.length || 0;
    totalIssues += issuesCountBySeverity[severity];
  });

  const allFilesCount = countFiles(snykIacTestScanResult);
  const filesWithIssuesCount = countFilesWithIssues(snykIacTestScanResult);
  const filesWithoutIssuesCount = allFilesCount - filesWithIssuesCount;

  return {
    resultsBySeverity,
    metadata: { projectName, orgName },
    counts: {
      ignores: 0,
      filesWithIssues: filesWithIssuesCount,
      filesWithoutIssues: filesWithoutIssuesCount,
      issues: totalIssues,
      issuesBySeverity: issuesCountBySeverity,
    },
  };
}

function countFilesWithIssues(results?: Results): number {
  if (results && results.vulnerabilities) {
    const files = new Set<string>();

    for (const vulnerability of results.vulnerabilities) {
      if (vulnerability.resource.file) {
        files.add(vulnerability.resource.file);
      }
    }

    return files.size;
  }

  return 0;
}

function countFiles(results?: Results): number {
  if (results && results?.resources) {
    const files = new Set<string>();

    for (const resource of results.resources) {
      if (resource.file) {
        files.add(resource.file);
      }
    }

    return files.size;
  }

  return 0;
}

function formatSnykIacTestScanResultNewOutput(
  snykIacTestScanResult: Results | undefined,
): FormattedOutputResultsBySeverity {
  const resultsBySeverity = {} as FormattedOutputResultsBySeverity;

  if (snykIacTestScanResult?.vulnerabilities) {
    snykIacTestScanResult.vulnerabilities.forEach((vulnerability) => {
      if (!resultsBySeverity[vulnerability.severity]) {
        resultsBySeverity[vulnerability.severity] = [];
      }

      resultsBySeverity[vulnerability.severity]!.push({
        issue: formatSnykIacTestScanVulnerability(vulnerability),
        targetFile: vulnerability.resource.file,
        projectType: vulnerability.resource.type,
      });
    });
  }

  return resultsBySeverity;
}

function formatSnykIacTestScanVulnerability(
  vulnerability: Vulnerability,
): Issue {
  return {
    id: vulnerability.rule.id,
    severity: vulnerability.severity,
    title: vulnerability.rule.title,
    lineNumber: vulnerability.resource.line,
    cloudConfigPath: formatCloudConfigPath(vulnerability),
    issue: vulnerability.rule.title,
    impact: vulnerability.rule.description,
    resolve: '',
    documentation: formatDocumentation(vulnerability),
  };
}

function formatCloudConfigPath(vulnerability: Vulnerability): string[] {
  const cloudConfigPath = vulnerability.resource.id.split('.');

  if (vulnerability.resource.path) {
    cloudConfigPath.push(...vulnerability.resource.path);
  }

  return cloudConfigPath;
}

function formatDocumentation(vulnerability: Vulnerability) {
  return `https://snyk.io/security-rules/${vulnerability.rule.id}`;
}
