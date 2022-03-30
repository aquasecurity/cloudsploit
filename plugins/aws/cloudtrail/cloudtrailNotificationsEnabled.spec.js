var expect = require('chai').expect;
const cloudtrailNotificationsEnabled = require('./cloudtrailNotificationsEnabled');

const describeTrails = [
    {
        "Name": "codepipeline-source-trail",
        "S3BucketName": "codepipeline-cloudtrail-placeholder-bucket-us-east-1",
        "S3KeyPrefix": "cloud-trail-000011112222-06bac57c-6f83-44ce-b54e-45af1ca29746",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": false,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:000011112222:trail/codepipeline-source-trail",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": true,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "trail-1",
        "S3BucketName": "aws-logs-000011112222-us-east-1",
        "S3KeyPrefix": "trail1",
        "SnsTopicName": "arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1",
        "SnsTopicARN": "arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:000011112222:trail/trail-1",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];
const listTopics =[
            {
                "TopicArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic"
            },
            {
                "TopicArn": "arn:aws:sns:us-east-1:000011112222:aqua-cspm-sns-000011112222"
            },
            {
                "TopicArn": "arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1"
            }
];

const getTopicAttributes =[
    {
        "Attributes": {
            "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\"SNS:Publish\"],\"Resource\":\"arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1\",\"Condition\":{\"StringEquals\":{\"AWS:SourceOwner\":\"000011112222\"}}},{\"Sid\":\"AWSCloudTrailSNSPolicy20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"SNS:Publish\",\"Resource\":\"arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:us-east-1:000011112222:trail/trail-1\"}}}]}",
            "Owner": "000011112222",
            "SubscriptionsPending": "0",
            "TopicArn": "arn:aws:sns:us-east-1:000011112222:aws-cloudtrail-logs-000011112222-8260eca1",
            "EffectiveDeliveryPolicy": "{\"http\":{\"defaultHealthyRetryPolicy\":{\"minDelayTarget\":20,\"maxDelayTarget\":20,\"numRetries\":3,\"numMaxDelayRetries\":0,\"numNoDelayRetries\":0,\"numMinDelayRetries\":0,\"backoffFunction\":\"linear\"},\"disableSubscriptionOverrides\":false}}",
            "SubscriptionsConfirmed": "0",
            "DisplayName": "",
            "SubscriptionsDeleted": "0"
        }
    },
    {}
];

const createCache = (describeTrails, listTopics, getTopicAttributes, describeTrailsErr, listTopicsErr, getTopicAttributesErr) => {
    let arn = (describeTrails && describeTrails.length) ? describeTrails[0].SnsTopicARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: describeTrails,
                    err: describeTrailsErr
                }
            },
        },
        sns: {
            listTopics: {
                'us-east-1': {
                    data: listTopics,
                    err: listTopicsErr
                }
            },
            getTopicAttributes: {
                'us-east-1': {
                    [arn]: {
                        data: getTopicAttributes,
                        err: getTopicAttributesErr
                    }
                }
            }
        
        }
    }
};

describe('cloudtrailNotificationsEnabled', function () {
    describe('run', function () {
        it('should PASS if CloudTrail trail is using active SNS topic', function (done) {
            const cache = createCache([describeTrails[1]], listTopics[2], getTopicAttributes[0]);
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('CloudTrail trail is using active SNS topic')
                done();
            });
        });

        it('should FAIL if CloudTrail trail SNS topic not found', function (done) {
            const cache = createCache([describeTrails[1]], listTopics[2], null, null, null, { message: 'An error occurred (NotFound) when calling the GetTopicAttributes operation: Topic does not exist', code : 'NotFound' } );
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('CloudTrail trail SNS topic not found')
                done();
            });
        });

        it('should PASS if no trail found', function (done) {
            const cache = createCache([]);
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No CloudTrail trails found')
                done();
            });
        });

        it('should UNKNOWN if unable to query for CloudTrail trails', function (done) {
            const cache = createCache([], [], null, { message: 'Unable to query for CloudTrail trails' });
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CloudTrail trails')
                done();
            });
        });

        it('should UNKNOWN if unable to query for SNS topics', function (done) {
            const cache = createCache([describeTrails[1]], [], null, null, { message: 'Unable to query for SNS topics' });
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SNS topics')
                done();
            });
        });

        it('should UNKNOWN if unable to query for SNS topic', function (done) {
            const cache = createCache([describeTrails[1]], listTopics[1], null, null, null, { message: 'Unable to query for SNS topic' });
            cloudtrailNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SNS topic')
                done();
            });
        });
    });
});
