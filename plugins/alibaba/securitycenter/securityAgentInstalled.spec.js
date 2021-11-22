var expect = require('chai').expect;
var securityAgentInstalled = require('./securityAgentInstalled.js');

const describeFieldStatistics = [
    {
		"GroupCount": 1,
		"ExposedInstanceCount": 0,
		"RiskInstanceCount": 0,
		"TencentInstanceCount": 0,
		"InstanceSyncTaskCount": 0,
		"ImportantAssetCount": 0,
		"GeneralAssetCount": 1,
		"IdcInstanceCount": 0,
		"TestAssetCount": 0,
		"UnprotectedInstanceCount": 0,
		"InstanceCount": 1,
		"OfflineInstanceCount": 1,
		"VpcCount": 1,
		"AliYunInstanceCount": 1,
		"RegionCount": 1
    },
    {
		"GroupCount": 1,
		"ExposedInstanceCount": 0,
		"RiskInstanceCount": 0,
		"TencentInstanceCount": 0,
		"InstanceSyncTaskCount": 0,
		"ImportantAssetCount": 0,
		"GeneralAssetCount": 1,
		"IdcInstanceCount": 0,
		"TestAssetCount": 0,
		"UnprotectedInstanceCount": 2,
		"InstanceCount": 1,
		"OfflineInstanceCount": 1,
		"VpcCount": 1,
		"AliYunInstanceCount": 1,
		"RegionCount": 1
    }
];

const createCache = (describeFieldStatistics, describeFieldStatisticsErr) => {
    return {
        tds: {
            DescribeFieldStatistics: {
                'cn-hangzhou': {
                    data: describeFieldStatistics,
                    err: describeFieldStatisticsErr
                },
            }
        }
    };
};

describe('securityAgentInstalled', function () {
    describe('run', function () {
        it('should FAIL if there are unprotected assets', function (done) {
            const cache = createCache(describeFieldStatistics[1]);
            securityAgentInstalled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('There are 2 unprotected assets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if there are no unprotected assets', function (done) {
            const cache = createCache(describeFieldStatistics[0]);
            securityAgentInstalled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('There are no unprotected assets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query TDS field statistics', function (done) {
            const cache = createCache([], { err: 'Unable to query TDS field statictics' });
            securityAgentInstalled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query TDS field statistics');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 