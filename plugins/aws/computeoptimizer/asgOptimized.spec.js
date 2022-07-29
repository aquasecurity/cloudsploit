var expect = require('chai').expect;
var asgOptimized = require('./asgOptimized');

const getRecommendationSummaries =  [
    {
        "summaries": [
            {
                "name": "OPTIMIZED",
                "value": 1.0
            },
            {
                "name": "NOT_OPTIMIZED",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "AutoScalingGroup",
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
                "name": "OPTIMIZED",
                "value": 0.0
            },
            {
                "name": "NOT_OPTIMIZED",
                "value": 1.0
            }
        ],
        "recommendationResourceType": "AutoScalingGroup",
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
                "name": "OPTIMIZED",
                "value": 0.0
            },
            {
                "name": "NOT_OPTIMIZED",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "AutoScalingGroup",
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

describe('asgOptimized', function () {
    describe('run', function () {
        it('should PASS if All Auto Scalling Groups are optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[0]]);
            asgOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('All Auto Scaling groups are optimized');
                done();
            });
        });

        it('should FAIL if Auto Scalling Groups are not optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[1]]);
            asgOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('unoptimized Auto Scaling groups');
                done();
            });
        });

        it('should PASS if no recommendations found for Auto Scaling groups', function (done) {
            const cache = createCache([getRecommendationSummaries[2]]);
            asgOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No recommendations found for Auto Scaling groups');
                done();
            });
        });

        it('should PASS if no Compute Optimizer recommendation summaries found', function (done) {
            const cache = createCache([]);
            asgOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Compute Optimizer recommendation summaries found');
                done();
            });
        });

        it('should UNKNOWN if Unable to get recommendation summaries', function (done) {
            const cache = createCache(null, { message: "Unable to get recommendation summaries" });
            asgOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get recommendation summaries');
                done();
            });
        });

        it('should not return anything if get recommendation summaries status response is not found', () => {
            asgOptimized.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});