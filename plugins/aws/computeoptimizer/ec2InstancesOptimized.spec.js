var expect = require('chai').expect;
var ec2InstancesOptimized = require('./ec2InstancesOptimized');

const getRecommendationSummaries =  [
    {
        "summaries": [
            {
                "name": "OPTIMIZED",
                "value": 1.0
            },
            {
                "name": "UNDER_PROVISIONED",
                "value": 0.0
            },
            {
                "name": "OVER_PROVISIONED",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "Ec2Instance",
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
                "name": "UNDER_PROVISIONED",
                "value": 0.0
            },
            {
                "name": "OVER_PROVISIONED",
                "value": 1.0
            }
        ],
        "recommendationResourceType": "Ec2Instance",
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
                "name": "UNDER_PROVISIONED",
                "value": 0.0
            },
            {
                "name": "OVER_PROVISIONED",
                "value": 0.0
            }
        ],
        "recommendationResourceType": "Ec2Instance",
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

describe('ec2InstancesOptimized', function () {
    describe('run', function () {
        it('should PASS if All EC2 instances are optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[0]]);
            ec2InstancesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('All EC2 instances are optimized');
                done();
            });
        });

        it('should FAIL if EC2 instance is not optimized', function (done) {
            const cache = createCache([getRecommendationSummaries[1]]);
            ec2InstancesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('over-provisioned EC2 instances');
                done();
            });
        });

        it('should PASS if EC2 instances have no recommendations enabled', function (done) {
            const cache = createCache([getRecommendationSummaries[2]]);
            ec2InstancesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EC2 instances have no recommendations enabled');
                done();
            });
        });

        it('should PASS if no Compute Optimizer recommendation summaries found', function (done) {
            const cache = createCache([]);
            ec2InstancesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Compute Optimizer recommendation summaries found');
                done();
            });
        });

        it('should UNKNOWN if Unable to get recommendation summaries', function (done) {
            const cache = createCache(null, { message: "Unable to get recommendation summaries" });
            ec2InstancesOptimized.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get recommendation summaries');
                done();
            });
        });

        it('should not return anything if get recommendation summaries status response is not found', () => {
            ec2InstancesOptimized.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});