var expect = require('chai').expect;
var ebsVolumesOptimized = require('./ebsVolumesOptimized');

const getRecommendationSummaries =  [
    {
        "summaries": [
            {
                "name": "Optimized",
                "value": 1.0
            },
            {
                "name": "NotOptimized",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "EbsVolume",
        "accountId": "000011112222",
        "currentPerformanceRiskRatings": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "veryLow": 0
        }
    },
    {
        "summaries": [
            {
                "name": "Optimized",
                "value": 0.0
            },
            {
                "name": "NotOptimized",
                "value": 1.0
            }
        ],
        "recommendationResourceType": "EbsVolume",
        "accountId": "000011112222",
        "currentPerformanceRiskRatings": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "veryLow": 0
        }
    },
    {
        "summaries": [
            {
                "name": "Optimized",
                "value": 0.0
            },
            {
                "name": "NotOptimized",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "EbsVolume",
        "accountId": "000011112222",
        "currentPerformanceRiskRatings": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "veryLow": 0
        }
    },
];


const createCache = (recommendation, recommendationErr) => {
    return {
        computeoptimizer: {
            getRecommendationSummaries: {
                'us-east-1': {
                    err: recommendationErr,
                    data: recommendation
                },
            },
        },
    };
};

describe('ebsVolumesOptimized', function () {
    describe('run', function () {
        it('should PASS if All EBS volumes are optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[0]]);
            ebsVolumesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('All EBS volumes are optimized');
                done();
            });
        });

        it('should FAIL if EBS volumes are not optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[1]]);
            ebsVolumesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('unoptimized EBS volumes');
                done();
            });
        });

        it('should PASS if EBS volumes have no recommendations found for EBS volumes', function (done) {
            const cache = createCache([getRecommendationSummaries[2]]);
            ebsVolumesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No recommendations found for EBS volumes');
                done();
            });
        });

        it('should PASS if No Compute Optimizer recommendation summaries found', function (done) {
            const cache = createCache([]);
            ebsVolumesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Compute Optimizer recommendation summaries found');
                done();
            });
        });

        it('should UNKNOWN if Unable to get recommendation summaries', function (done) {
            const cache = createCache(null, { message: "Unable to get recommendation summaries" });
            ebsVolumesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get recommendation summaries');
                done();
            });
        });

        it('should not return anything if get recommendation summaries status response is not found', () => {
            ebsVolumesOptimized.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});