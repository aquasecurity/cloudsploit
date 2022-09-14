var expect = require('chai').expect;
const servicesInUse = require('./servicesInUse');

const describeConfigurationRecorderStatus = [
    {
        "name": "default",
        "lastStartTime": "2022-09-01T15:01:18.132000+05:00",
        "lastStopTime": "2022-06-10T18:14:00.397000+05:00",
        "recording": true,
        "lastStatus": "SUCCESS",
        "lastStatusChangeTime": "2022-09-01T15:01:30.271000+05:00"
    },

]

const getDiscoveredResourceCounts =[
    {
        "resourceCounts": [
            {
                "resourceType": "AWS::IAM::Role",
                "count": 100
            },
            {
                "resourceType": "AWS::IAM::Policy",
                "count": 48
            },
            {
                "resourceType": "AWS::KMS::Key",
                "count": 28
            },
            {
                "resourceType": "AWS::S3::Bucket",
                "count": 24
            },
            {
                "resourceType": "AWS::EC2::SecurityGroup",
                "count": 17
            },
            {
                "resourceType": "AWS::CodeDeploy::DeploymentConfig",
                "count": 17
            },
            {
                "resourceType": "AWS::IAM::User",
                "count": 11
            },
            {
                "resourceType": "AWS::EC2::Subnet",
                "count": 8
            },
            {
                "resourceType": "AWS::CloudWatch::Alarm",
                "count": 5
            },
            {
                "resourceType": "AWS::EC2::RouteTable",
                "count": 4
            },
            {
                "resourceType": "AWS::EC2::VPC",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::NetworkInterface",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::NetworkAcl",
                "count": 3
            },
            {
                "resourceType": "AWS::SNS::Topic",
                "count": 3
            },
            {
                "resourceType": "AWS::Route53Resolver::ResolverRuleAssociation",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::InternetGateway",
                "count": 2
            },
            {
                "resourceType": "AWS::AccessAnalyzer::Analyzer",
                "count": 2
            },
            {
                "resourceType": "AWS::DMS::ReplicationSubnetGroup",
                "count": 2
            },
            {
                "resourceType": "AWS::CloudFormation::Stack",
                "count": 2
            },
            {
                "resourceType": "AWS::CloudTrail::Trail",
                "count": 2
            },
            {
                "resourceType": "AWS::ApiGatewayV2::Stage",
                "count": 2
            },
            {
                "resourceType": "AWS::Backup::BackupVault",
                "count": 2
            },
            {
                "resourceType": "AWS::SQS::Queue",
                "count": 1
            },
            {
                "resourceType": "AWS::EC2::Instance",
                "count": 1
            },
            {
                "resourceType": "AWS::Route53Resolver::ResolverRule",
                "count": 1
            },
            {
                "resourceType": "AWS::RDS::DBSubnetGroup",
                "count": 1
            },
            {
                "resourceType": "AWS::Redshift::ClusterParameterGroup",
                "count": 1
            },
            {
                "resourceType": "AWS::S3::AccountPublicAccessBlock",
                "count": 1
            },
            {
                "resourceType": "AWS::ApiGateway::Stage",
                "count": 1
            },
            {
                "resourceType": "AWS::RDS::DBSnapshot",
                "count": 1
            },
            {
                "resourceType": "AWS::SSM::AssociationCompliance",
                "count": 1
            },
            {
                "resourceType": "AWS::EC2::LaunchTemplate",
                "count": 1
            },
            {
                "resourceType": "AWS::Lambda::Function",
                "count": 1
            },
            {
                "resourceType": "AWS::Redshift::ClusterSubnetGroup",
                "count": 1
            },
            {
                "resourceType": "AWS::RDS::DBSecurityGroup",
                "count": 1
            },
            {
                "resourceType": "AWS::CodeBuild::Project",
                "count": 1
            },
            {
                "resourceType": "AWS::ApiGatewayV2::Api",
                "count": 1
            },
            {
                "resourceType": "AWS::EC2::Volume",
                "count": 1
            },
            {
                "resourceType": "AWS::ECR::Repository",
                "count": 1
            },
            {
                "resourceType": "AWS::IAM::Group",
                "count": 1
            },
            {
                "resourceType": "AWS::SSM::ManagedInstanceInventory",
                "count": 1
            },
            {
                "resourceType": "AWS::ApiGateway::RestApi",
                "count": 1
            }
        ]
    },
    {
        "totalDiscoveredResources": 311,
        "resourceCounts": [
            {
                "resourceType": "AWS::IAM::Role",
                "count": 100
            },
            {
                "resourceType": "AWS::IAM::Policy",
                "count": 48
            },
            {
                "resourceType": "AWS::EC2::SecurityGroup",
                "count": 17
            },
            {
                "resourceType": "AWS::IAM::User",
                "count": 11
            },
            {
                "resourceType": "AWS::EC2::Subnet",
                "count": 8
            },
            {
                "resourceType": "AWS::CloudWatch::Alarm",
                "count": 5
            },
            {
                "resourceType": "AWS::EC2::RouteTable",
                "count": 4
            },
            {
                "resourceType": "AWS::EC2::VPC",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::NetworkInterface",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::NetworkAcl",
                "count": 3
            },
            {
                "resourceType": "AWS::EC2::Volume",
                "count": 1
            },
            {
                "resourceType": "AWS::IAM::Group",
                "count": 1
            },
          
        ]
    }
]

const createCache = (recorderStatus, resourcesCount, recordStatusErr, resourcesCountErr) => {
    return {
        configservice: {
            describeConfigurationRecorderStatus: {
                'us-east-1': {
                    data: recorderStatus,
                    err: recordStatusErr
                },
            },
            getDiscoveredResourceCounts: {
                'us-east-1': {
                        data: resourcesCount,
                        err: resourcesCountErr
                },
            },
        },
    };
};

describe('servicesInUse', () => {
    describe('run', () => {   
        it('should PASS if only allowed services are being usedd', (done) => {
            const cache = createCache([describeConfigurationRecorderStatus[0]], getDiscoveredResourceCounts[1]["resourceCounts"]);
            servicesInUse.run(cache, {permitted_services_list: 'iam, ec2, cw, cfn'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Only allowed services are being used');
                done();
            });
        });

        it('should FAIL if unpermitted services are being used', (done) => {
            const cache = createCache([describeConfigurationRecorderStatus[0]], getDiscoveredResourceCounts[0]["resourceCounts"]);
            servicesInUse.run(cache, {unpermitted_services_list: 'iam'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('These unpermitted services are being used');
                done();
            });
        });

        it('should FAIL if Config service is not enabled', function (done) {
            const cache = createCache([]);
            servicesInUse.run(cache, {permitted_services_list: 'iam, ec2, cw, cfn'}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Config service is not enabled');
                done();
            });
        });

        it('should UNKNOWN if Unable to query config service', (done) => {
            const cache = createCache(null, null, null);
            servicesInUse.run(cache, {permitted_services_list: 'iam, ec2, cw, cfn'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query config service');
                done();
            });
        });
        
    })

})
