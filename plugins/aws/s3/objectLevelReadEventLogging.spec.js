var expect = require('chai').expect;
const objectLevelReadLogging = require('./objectLevelReadEventLogging');

const listBuckets = [
    {
        Name: 'elasticbeanstalk-us-east-1-111122223333',
        CreationDate: '2020-08-20T17:42:52.000Z'
    }
];

const trails = [
    {
        "Name": "trail-1",
        "S3BucketName": "elasticbeanstalk-us-east-1-111122223333",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": true,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-1",
        "LogFileValidationEnabled": true,
        "KmsKeyId": "a14dea26-1459-4f62-ab85-d5a54293a495",
        "HasCustomEventSelectors": true,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    },
    {
        "Name": "trail-2",
        "S3BucketName": "'elasticbeanstalk-us-east-1-111122223333",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": false,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-2",
        "LogFileValidationEnabled": false,
        "HasCustomEventSelectors": false,
        "HasInsightSelectors": false,
        "IsOrganizationTrail": false
    }
];

const getEventSelectors = [
    {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456654321:trail/trail-1",
        "EventSelectors": [
            {
                "ReadWriteType": "ReadOnly",
                "IncludeManagementEvents": true,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": [
                            "arn:aws:s3"
                        ]
                    }
                ],
                "ExcludeManagementEventSources": []
            }
        ]
    },
    {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/test-trail-1",
        "EventSelectors": [
            {
                "ReadWriteType": "ReadOnly",
                "IncludeManagementEvents": false,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": [
                            "arn:aws:s3:::test-bucket-130/"
                        ]
                    }
                ],
                "ExcludeManagementEventSources": []
            }
        ]
    },
    {
        
        "TrailARN": "arn:aws:cloudtrail:us-east-1:672202477801:trail/trail-1",
         "AdvancedEventSelectors": [
            {
                "FieldSelectors": [
                   {
                        "Field": "eventCategory",
                        "Equals": [
                        "Data"
                       ]
                    },
                    {
                        "Field": "resources.type",
                        "Equals": [
                            "AWS::S3::Object"
                        ]
                    }
                ]
            },
            {
                "Name": "Management events selector",
                "FieldSelectors": [
                    {
                        "Field": "eventCategory",
                        "Equals": [
                            "Management"
                        ]
                    }
                ]
            }
        ]
    }
];

const createCache = (buckets, describeTrails, getEventSelectors) => {
    var trailARN = (describeTrails && describeTrails.length) ? describeTrails[0].TrailARN : null;
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;

    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            },
        },
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                     data: describeTrails
                },
            },
            getEventSelectors: {
                'us-east-1': {
                    [trailARN]: {
                            data: getEventSelectors
                    }
                }
            }
        },
    
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            }
        },
        cloudtrail: {
            describeTrails: {
                'us-east-1': null
            }
        }
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing S3 buckets'
                    },
                },
            }
        },
    };
};

describe('objectLevelReadLogging', function () {
    describe('run', function () {
        it('should PASS no S3 bucket found', function (done) {
            const cache = createCache([],trails[0],getEventSelectors[0]);
            objectLevelReadLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No S3 buckets Founds');
                done();
            });
        });

        it('should FAIL if S3 bucket doesnot have object-level logging for read events', function (done) {
            const cache = createCache(listBuckets,[trails[0]],getEventSelectors[1]);
            objectLevelReadLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not has object-level logging for read events');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if object-level logging is enable for read events', function (done) {
            const cache = createCache(listBuckets,[trails[0]],getEventSelectors[0]);
            objectLevelReadLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket has object-level logging for read events');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createErrorCache();
            objectLevelReadLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if S3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            objectLevelReadLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});