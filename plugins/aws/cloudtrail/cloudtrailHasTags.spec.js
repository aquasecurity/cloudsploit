var expect = require('chai').expect;
var cloudtrailHasTags = require('./cloudtrailHasTags');

const trails = [
    {
        "Name": "trail-1",
        "S3BucketName": "cloudtrail-bucket",
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
];

const listTags = [
    {
        ResourceTagList : [
            {TagsList: []}
            ]
    },
    {
       ResourceTagList : [
            {TagsList: [
                {key: 'value'}
            ]}
            ]
    }
]

const createCache = (trails, listTags) => {
    var trailARN = (trails && trails.length) ? trails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails,
                },
            },
            listTags: {
                'us-east-1': {
                    [trailARN]: {
                        data: listTags
                    }
                }
            }
        }
    };
};

const createErrorCache = (trails) => {
    var trailARN = (trails && trails.length) ? trails[0].TrailARN : null;
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    err: {
                        message: 'error describing trails'
                    },
                },
            },
            listTags: {
                'us-east-1': {
                    [trailARN]: {
                        err: {
                            message: 'error getting trail status'
                        }
                    }
                }
            }
        },
    };
};

describe('cloudtrailHasTags', function () {
    describe('run', function () {

        it('should UNKNOWN if unable to query for trails', function (done) {
            const cache = createErrorCache();
            cloudtrailHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for CloudTrail trails');
                done();
            });
        });
        it('should Passing result if cloud trail is not enabled', function (done) {
        const cache = createCache([], null);
        cloudtrailHasTags.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].region).to.equal('us-east-1');
            expect(results[0].message).to.include('CloudTrail is not enabled');
            done();
        });
    });

    it('should Unknown result if unable to query listTags', function (done) {
        const cache = createCache([trails[0]], null);
        cloudtrailHasTags.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].region).to.equal('us-east-1');
            expect(results[0].message).to.include('Unable to list trail tags');
            done();
        });
    });

     it('should Failing result if trails have no tags', function (done) {
        const cache = createCache([trails[0]], listTags[0]);
        cloudtrailHasTags.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].region).to.equal('us-east-1');
            expect(results[0].message).to.include('CloudTrail trail does not have tags');
            done();
        });
    });
   it('should Passing result if trails have tags', function (done) {
        const cache = createCache([trails[0]], listTags[1]);
        cloudtrailHasTags.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].region).to.equal('us-east-1');
            expect(results[0].message).to.include('CloudTrail trail has tags');
            done();
        });
    });
    });
});
