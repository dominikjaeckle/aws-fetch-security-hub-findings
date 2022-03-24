import os
import json
import yaml
from datetime import datetime
from pydantic import BaseModel
from typing import List

class Finding(BaseModel):
    environment: str = ''
    account_id: str = ''
    created_at: str = ''
    updated_at: str = ''
    compliance_status: str = ''
    title: str = ''
    description: str = ''
    recommendation_text: str = ''
    recommendation_url: str = ''
    workflow_state: str = ''
    workflow_status: str = ''
    record_state: str = ''
    severity_label: str = ''

def fetch_findings(environment: str, filterstr: str, sortcriteria: str) -> List[Finding]:
    '''
        Fetches the findings from a given aws account following a certain filter and sorting criteria
    '''

    os.environ['AWS_PROFILE'] = environment

    findings_raw = os.popen(f'aws securityhub get-findings --filters {filterstr} --sort-criteria {sortcriteria} --page-size 100 --max-items 1000')
    findings_json = json.loads(findings_raw.read())['Findings']

    findings: List[Finding] = []
    for f in findings_json:
        finding = Finding()
        finding.environment = environment
        finding.account_id = f['AwsAccountId']
        finding.created_at = f['CreatedAt']
        finding.updated_at = f['UpdatedAt']
        finding.compliance_status = f["Compliance"]["Status"] if ("Compliance" in f.keys()) else ''
        finding.title = f["Title"]
        finding.description = f["Description"]
        finding.recommendation_text = f["Remediation"]["Recommendation"]["Text"] if ("Remediation" in f.keys()) else ''
        finding.recommendation_url = f["Remediation"]["Recommendation"]["Url"] if ("Remediation" in f.keys() and "Url" in f["Remediation"]["Recommendation"].keys()) else ''
        finding.workflow_state = f["WorkflowState"]
        finding.workflow_status = f["Workflow"]["Status"]
        finding.record_state = f["RecordState"]
        finding.severity_label = f["FindingProviderFields"]["Severity"]["Label"]

        findings.append(finding)

    return findings

def create_valid_html(findings: List[Finding]):
    '''
        Creates a html report from the given findings
    '''

    file = open(f'security_findings_{datetime.now().strftime("%Y%m%d")}.html','w')
    html = '''
        <html>
        <head>
            <style>
                body, html {
                    font-family: Arial, sans-serif;
                    font-size: 0.9em;
                }
                table {
                    width: 100%;
                    font-size: 0.4em;
                }
                table tr th {
                    background-color: whitesmoke;
                }
                table, td, th {
                    border:1px solid black;
                    border-collapse: collapse;
                }
                td, th {
                    padding: 5px;
                }
            </style>
        </head>
        <body>
            <h1>Security Findings<h1>
            <table>
    '''

    if (len(findings) > 0):
        html += '<tr>'
        html += '<th>index</th>'
        for key, value in findings[0]:
            html += f'<th>{key}</th>'
        html += '</tr>'

    index = 0
    for finding in findings:
        html += f'<tr style="background-color: {"#ffcfcc" if finding.severity_label == "HIGH" else "none"}">'
        html += f'<td>{index}</td>'
        for key, value in finding:
            html += f'<td>{value}</td>'
        html += '</tr>'
        index += 1

    html += '</table></body></html>'

    file.write(html)
    file.close()

if __name__ == '__main__':
    '''
        Fetches all security findings that follow a certain filter criteria.
        The script is executed on the locally configered AWS environments and requires that awssso was run before.

        https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html
    '''
    settings = None
    with open('settings.yaml', 'r') as stream:
        settings = yaml.safe_load(stream)

    # fetch environments and build filters and sorting criteria
    environments = settings['accounts']
    filterstr = '\'{' + ','.join(f'"{x["filter_name"]}": [{{"Value": "{x["value"]}", "Comparison": "{x["comparison"]}"}}]' for x in settings['filters'])+ '}\''
    sortcriteria = f'\'{{"Field": "{settings["sort_criteria"]["field"]}", "SortOrder": "{settings["sort_criteria"]["sort_order"]}"}}\''

    # fetch all findings and create a html report
    findings = [finding for env in environments for finding in fetch_findings(environment=env, filterstr=filterstr, sortcriteria=sortcriteria)]
    create_valid_html(findings=findings)

    print(f'Finished, Found: {len(findings)} finding(s)')
    