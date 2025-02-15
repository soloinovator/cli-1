import * as capitalize from 'lodash.capitalize';
import chalk from 'chalk';
import { EOL } from 'os';
import { iacRemediationTypes } from '../../../../iac/constants';
import { printPath } from '../../../remediation-based-format-issues';
import { colors, contentPadding } from '../utils';
import { FormattedOutputResult, Issue } from '../types';
import { Options } from './types';

export function formatIssue(
  result: FormattedOutputResult,
  options?: Options,
): string {
  const titleOutput = formatTitle(result.issue);

  const propertiesOutput = formatProperties(result, options);
  return (
    contentPadding +
    titleOutput +
    EOL +
    contentPadding +
    propertiesOutput.join(EOL + contentPadding)
  );
}

function formatTitle(issue: Issue): string {
  const severity = issue.severity;
  const titleOutput = colors.severities[severity](
    `[${capitalize([issue.severity])}] ${chalk.bold(issue.title)}`,
  );

  return titleOutput;
}

function formatInfo(issue: Issue): string | undefined {
  const issueDesc = issue.issue;
  const issueImpact = issue.impact;

  if (!issueDesc) {
    return issueImpact;
  }

  if (!issueImpact) {
    return issueDesc;
  }

  return `${issueDesc}${!issueDesc.endsWith('.') ? '.' : ''} ${issueImpact}`;
}

function formatProperties(
  result: FormattedOutputResult,
  options?: Options,
): string[] {
  const remediationKey = iacRemediationTypes?.[result.projectType];

  const properties = [
    ['Info', formatInfo(result.issue)],
    [
      'Rule',
      result.issue.isGeneratedByCustomRule
        ? `custom rule ${result.issue.id}`
        : chalk.underline(result.issue.documentation || ''),
    ],
    ['Path', printPath(result.issue.cloudConfigPath, 0)],
    [
      'File',
      `${result.targetFile}${
        options?.shouldShowLineNumbers &&
        isValidLineNumber(result.issue.lineNumber)
          ? `:${result.issue.lineNumber}`
          : ''
      }`,
    ],
    [
      'Resolve',
      remediationKey && result.issue.remediation?.[remediationKey]
        ? result.issue.remediation[remediationKey]
        : result.issue.resolve,
    ],
  ].filter(([, val]) => !!val) as [string, string][];

  const maxPropertyNameLength = Math.max(
    ...properties.map(([key]) => key.length),
  );

  return properties.map(
    ([key, value]) =>
      `${key}: ${' '.repeat(maxPropertyNameLength - key.length)}${value}`,
  );
}

function isValidLineNumber(lineNumber: number | undefined): boolean {
  return (
    typeof lineNumber === 'number' && lineNumber! > 0 && lineNumber! % 1 === 0
  );
}
