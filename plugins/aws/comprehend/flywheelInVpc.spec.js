var expect = require('chai').expect;
var flywheelInVpc = require('./flywheelInVpc')

const listFlywheels = [
    {
        "FlywheelArn": "arn:aws:comprehend:us-east-1:1234567:flywheel/test",
        "DataLakeS3Uri": "s3://new-test-bucket/test/schemaVersion=1/20240325T065158Z/",
        "Status": "ACTIVE",
        "ModelType": "DOCUMENT_CLASSIFIER",
        
    },
    {
        "FlywheelArn": "arn:aws:comprehend:us-east-1:1234567:flywheel/test2",
            "DataLakeS3Uri": "s3://new-test-bucket2/test/schemaVersion=1/20240325T054365Z/",
            "Status": "ACTIVE",
            "ModelType": "DOCUMENT_CLASSIFIER",
    }
];

const describeFlywheel = [
    {
        "FlywheelProperties": {
            "FlywheelArn": "arn:aws:comprehend:us-east-1:1234567:flywheel/test",
            "DataAccessRoleArn": "arn:aws:iam::1234567:role/service-role/AmazonComprehendServiceRole-test",
            "TaskConfig": {
                "LanguageCode": "en",
                "DocumentClassificationConfig": {
                    "Mode": "MULTI_CLASS",
                    "Labels":[
                         "comedy"
                        ]
                    } 
                },
            "DataLakeS3Uri": "s3://new-test-bucket/test/schemaVersion=1/20240325T065158Z/",
            "DataSecurityConfig": {
                "VpcConfig": {
                    "SecurityGroupIds": [
                        "sg-05d802ffebeec4ce9"
                    ],
                    "Subnets": [
                        "subnet-090543c3cc7bee455"
                    ]
                }
            },
            "Status": "ACTIVE",
            "ModelType": "DOCUMENT_CLASSIFIER"
        }
    },
    {
        "FlywheelProperties": {
            "FlywheelArn": "arn:aws:comprehend:us-east-1:1234567:flywheel/test",
            "DataAccessRoleArn": "arn:aws:iam::1234567:role/service-role/AmazonComprehendServiceRole-test",
            "TaskConfig": {
                "LanguageCode": "en",
                "DocumentClassificationConfig": {
                    "Mode": "MULTI_CLASS",
                    "Labels":[
                         "comedy"
                        ]
                    } 
                },
            "DataLakeS3Uri": "s3://new-test-bucket/test/schemaVersion=1/20240325T065158Z/",
            "DataSecurityConfig": {},
            "Status": "ACTIVE",
            "ModelType": "DOCUMENT_CLASSIFIER"
        }
    }
];


const createCache = (listFlywheels, describeFlywheel, listFlywheelsErr, getFlywheelErr) => {
    var flywheelArn = (listFlywheels && listFlywheels.length) ? listFlywheels[0].FlywheelArn: null;
    return {
        comprehend: {
            listFlywheels: {
                'us-east-1': {
                    err: listFlywheelsErr,
                    data: listFlywheels
                },
            },
            describeFlywheel: {
                'us-east-1': {
                    [flywheelArn]: {
                        data: describeFlywheel,
                        err: getFlywheelErr
                    }
                }
            }
        }
    };
};

describe('flywheelInVpc', function () {
    describe('run', function () {
        it('should PASS if Comprehend Flywheel has Vpc configured', function (done) {
            const cache = createCache([listFlywheels[0]],describeFlywheel[0]);
            flywheelInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Comprehend Flywheel have not Vpc configured', function (done) {
            const cache = createCache([listFlywheels[1]], describeFlywheel[1]);
            flywheelInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Comprehend flywheel found', function (done) {
            const cache = createCache([]);
            flywheelInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe Comprehend flywheell', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to describe Comprehend flywheel" });
            flywheelInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
     });
})
