var expect = require('chai').expect;
var privateCustomModel = require('./privateCustomModel');

const listCustomModels = [
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "modelName": "model2",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    },
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/vjqsydtdhkpz",
        "modelName": "testmodel2",
        "creationTime": "2023-11-28T11:29:18.655000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    }
];

const getCustomModel = [
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "modelName": "model2",
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/lo7152tvvl3f",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "modelKmsKeyArn": "arn:aws:kms:us-east-1:11223344:key/29c2507e-ba0d-4b70-b20d-8b30b761685b",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "trainingMetrics": {
            "trainingLoss": 1.7109375
        },
        "validationMetrics": [],
        "creationTime": "2023-11-29T10:45:43.056000+00:00"
    },
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/vjqsydtdhkpz",
        "modelName": "testmodel2",
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/iuvltioettou",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "trainingMetrics": {
            "trainingLoss": 1.7109375
        },
        "validationMetrics": [],
        "creationTime": "2023-11-28T11:29:18.655000+00:00"
    }
];

const listModelCustomizationJobs = [
    {
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/lo7152tvvl3f",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "jobName": "second",
        "status": "Completed",
        "lastModifiedTime": "2023-11-29T11:36:48.302000+00:00",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "endTime": "2023-11-29T11:36:47.666000+00:00",
        "customModelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "customModelName": "model2"
    },
    {
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/nn23m2vejr54",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "jobName": "testjobformodel2",
        "status": "Failed",
        "lastModifiedTime": "2023-11-29T09:08:17.414000+00:00",
        "creationTime": "2023-11-29T08:47:00.690000+00:00",
        "endTime": "2023-11-29T09:08:17.335000+00:00",
        "customModelName": "testmodel2"
    },
]

const getModelCustomizationJob = [
    {
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/nn23m2vejr54",
        "jobName": "second",
        "outputModelName": "model2",
        "outputModelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "clientRequestToken": "0da79509-df0a-4bec-9dab-c13a33584247",
        "roleArn": "arn:aws:iam::11223344:role/service-role/test-role-bedrock",
        "status": "Completed",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "lastModifiedTime": "2023-11-29T11:36:48.302000+00:00",
        "endTime": "2023-11-29T11:36:47.666000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "validationDataConfig": {
            "validators": []
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "outputModelKmsKeyArn": "arn:aws:kms:us-east-1:672202477801:key/29c2507e-ba0d-4b70-b20d-8b30b761685b",
        "validationMetrics": [],
        "vpcConfig": {
            "subnetIds": [
                "subnet-123",
            ],
            "securityGroupIds": [
                "sg-0931c3a02deed68f5"
            ]
        }
    },
    {
        "jobArn": "arn:aws:bedrock:us-east-1:11223344:model-customization-job/amazon.titan-text-lite-v1:0:4k/lo7152tvvl3f",
        "jobName": "first",
        "outputModelName": "testmodel2",
        "outputModelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "clientRequestToken": "0da79509-df0a-4bec-9dab-c13a33584247",
        "roleArn": "arn:aws:iam::11223344:role/service-role/test-role-bedrock",
        "status": "Completed",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "lastModifiedTime": "2023-11-29T11:36:48.302000+00:00",
        "endTime": "2023-11-29T11:36:47.666000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "hyperParameters": {
            "batchSize": "2",
            "epochCount": "2",
            "learningRate": "0.00001",
            "learningRateWarmupSteps": "0"
        },
        "trainingDataConfig": {
            "s3Uri": "s3://bedrockbuckettest/trainigdata.jsonl"
        },
        "validationDataConfig": {
            "validators": []
        },
        "outputDataConfig": {
            "s3Uri": "s3://bedrockbuckettest"
        },
        "outputModelKmsKeyArn": "arn:aws:kms:us-east-1:672202477801:key/29c2507e-ba0d-4b70-b20d-8b30b761685b",
        "validationMetrics": [],
        "vpcConfig": {
            "subnetIds": [
                "subnet-234",
            ],
            "securityGroupIds": [
                "sg-0931c3a02deed68f5"
            ]
        }
    }
];

const describeRouteTables = [
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          }
        ],
        "Tags": [],
        "VpcId": "vpc-123",
        "OwnerId": "000011112222"
    },
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            },
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "igw-sedwednkq",
                "Origin": "CreateRouteTable",
                "State": "active"
            }

        ],
        "Tags": [],
        "VpcId": "vpc-234",
        "OwnerId": "000011112222"
    }
];

const describeSubnets = [
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-123",
        "VpcId": "vpc-123",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    },
    {
        "AvailabilityZone": "us-east-1c",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.16.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-234",
        "VpcId": "vpc-234",
        "OwnerId": "000011112222",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-1:000011112222:subnet/subnet-aac6b3e7"
    }
];

const createCache = (customModel, listJobs, getCustomModel, getJobs, subnets, routeTables, customModelErr, listJobsErr, getCustomModelErr, getJobErr) => {
    var modelName = (customModel && customModel.length) ? customModel[0].modelName: null;
    var jobName = (listJobs && listJobs.length) ? listJobs[0].jobArn: null;
    return {
        bedrock: {
            listCustomModels: {
                'us-east-1': {
                    err: customModelErr,
                    data: customModel
                },
            },
            listModelCustomizationJobs: {
                'us-east-1': {
                    err: listJobsErr,
                    data: listJobs
                },
            },
            getCustomModel: {
                'us-east-1': {
                    [modelName]: {
                        data: getCustomModel,
                        err: getCustomModelErr
                    }
                }
            },
            getModelCustomizationJob: {
                'us-east-1': {
                    [jobName]: {
                        data: getJobs,
                        err: getJobErr
                    }
                }
            }
        },
        ec2: {
            describeSubnets: {
                'us-east-1': {
                    data: subnets
                }
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                }
            }
        }
    };
};

describe('privateCustomModel', function () {
    describe('run', function () {
        it('should PASS if Bedrock Custom Model is a private model', function (done) {
            const cache = createCache([listCustomModels[1]], [listModelCustomizationJobs[0]],getCustomModel[0],getModelCustomizationJob[0],[describeSubnets[0]], [describeRouteTables[0]]);
            privateCustomModel.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Bedrock Custom Model have not Vpc configured', function (done) {
            const cache = createCache([listCustomModels[0]],[listModelCustomizationJobs[0]] ,getCustomModel[0],getModelCustomizationJob[1],[describeSubnets[0]], [describeRouteTables[0]]);
            privateCustomModel.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Bedrock Custom Model is not a private model', function (done) {
            const cache = createCache([listCustomModels[0]],[listModelCustomizationJobs[0]] ,getCustomModel[0],getModelCustomizationJob[0],[describeSubnets[1]], [describeRouteTables[1]]);
            privateCustomModel.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Bedrock custom model found', function (done) {
            const cache = createCache([]);
            privateCustomModel.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Bedrock custom model', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Bedrock Custom Model" });
            privateCustomModel.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
     });
})