import { Construct } from 'constructs'
import { App, TerraformStack } from 'cdktf'
import { AwsProvider, CloudwatchLogMetricFilter, CloudwatchLogMetricFilterConfig, CloudwatchLogMetricFilterMetricTransformation, CloudwatchMetricAlarm, CloudwatchMetricAlarmConfig, DataAwsCallerIdentity } from '@cdktf/provider-aws'

class MyStack extends TerraformStack {
  createMetricAndAlarm (name: string, pattern: string, actions: string[]) {
    const transformation: CloudwatchLogMetricFilterMetricTransformation[] = [{ name: name, namespace: 'LogMetrics', value: '1' }]
    const config : CloudwatchLogMetricFilterConfig = { logGroupName: 'CloudTrail/DefaultLogGroup', name: name, pattern: pattern, metricTransformation: transformation }
    new CloudwatchLogMetricFilter(this, `filter-${name}`, config)
    const alarmConfig : CloudwatchMetricAlarmConfig = { treatMissingData: 'notBreaching', alarmActions: actions, threshold: 0, namespace: 'LogMetrics', period: 300, metricName: name, statistic: 'Sum', alarmName: name, comparisonOperator: 'GreaterThanThreshold', evaluationPeriods: 1 }
    new CloudwatchMetricAlarm(this, `alarm-${name}`, alarmConfig)
  }

  constructor (scope: Construct, id: string) {
    super(scope, id)
    const provider = new AwsProvider(this, 'aws', { region: 'us-east-1' })
    const account = new DataAwsCallerIdentity(this, 'account')
    const snsAction = [`arn:aws:sns:${provider.region}:${account.accountId}:monitor`]

    // Remediation tips from https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#cis-3.1-remediation
    this.createMetricAndAlarm('CIS-3.1-UnauthorizedAPICalls', '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}', snsAction)
    this.createMetricAndAlarm('CIS-3.2-ConsoleSigninWithoutMFA', '{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes")}', snsAction)
    this.createMetricAndAlarm('CIS-3.3-RootAccountUsageAlarm', '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}', snsAction)
    this.createMetricAndAlarm('CIS-3.4-IAMPolicyChanges', '{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}', snsAction)
    this.createMetricAndAlarm('CIS-3.5-CloudTrailChanges', '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}', snsAction)
    this.createMetricAndAlarm('CIS-3.6-ConsoleAuthenticationFailure', '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}', snsAction)
    this.createMetricAndAlarm('CIS-3.7-DisableOrDeleteCMK', '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}', snsAction)
    this.createMetricAndAlarm('CIS-3.8-S3BucketPolicyChanges', '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}', snsAction)
    this.createMetricAndAlarm('CIS-3.9-AWSConfigChanges', '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}', snsAction)
    this.createMetricAndAlarm('CIS-3.10-SecurityGroupChanges', '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}', snsAction)
    this.createMetricAndAlarm('CIS-3.11-NetworkACLChanges', '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}', snsAction)
    this.createMetricAndAlarm('CIS-3.12-NetworkGatewayChanges', '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}', snsAction)
    this.createMetricAndAlarm('CIS-3.13-RouteTableChanges', '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}', snsAction)
    this.createMetricAndAlarm('CIS-3.14-VPCChanges', '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}', snsAction)
  }
}

const app = new App()
new MyStack(app, 'cis-benchmark-log-alarms')
app.synth()
