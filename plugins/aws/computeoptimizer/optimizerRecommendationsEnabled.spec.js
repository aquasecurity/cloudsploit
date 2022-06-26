var expect = require('chai').expect;
var optimizerRecommendationsEnabled = require('./optimizerRecommendationsEnabled');

const getRecommendationSummaries =  [
    {
        "summaries": [
            {
                "name": "Optimized",
                "value": 0.0
            },
            {
                "name": "NotOptimized",
                "value": 1.0,
                "reasonCodeSummaries": [
                    {
                        "name": "MemoryOverprovisioned",
                        "value": 1.0
                    },
                    {
                        "name": "MemoryUnderprovisioned",
                        "value": 0.0
                    }
                ]
            }
        ],
        "recommendationResourceType": "LambdaFunction",
        "accountId": "000011112222",
        "currentPerformanceRiskRatings": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "veryLow": 0
        }
    }
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

describe('optimizerRecommendationsEnabled', function () {
    describe('run', function () {
        it('should PASS if Compute Optimizer is Enabled', function (done) {
            const cache = createCache([getRecommendationSummaries[0]]);
            optimizerRecommendationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Compute Optimizer is Enabled');
                done();
            });
        });

        it('should FAIL if Compute Optimizer is not enabled', function (done) {
            const cache = createCache(null, {  message: 'Aws account is not registered for recommendation.', code: 'OptInRequiredException' });
            optimizerRecommendationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Compute Optimizer is not enabled');

                done();
            });
        });

        it('should UNKNOWN if Unable to get recommendation summaries', function (done) {
            const cache = createCache(null, { message: "Unable to get recommendation summaries" });
            optimizerRecommendationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get Compute Optimizer recommendation summaries');
                done();
            });
        });

        it('should not return anything if get recommendation summaries status response is not found', () => {
            optimizerRecommendationsEnabled.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});