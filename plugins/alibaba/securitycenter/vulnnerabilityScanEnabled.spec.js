var expect = require('chai').expect;
var vulnerabilityScanEnabled = require('./vulnerabilityScanEnabled.js');

var describeVulConfig =[
    {
        "TotalCount": 8,
        "TargetConfigs": [
          {
            "Type": "app",
            "Config": "on"
          },
          {
            "Type": "yum",
            "Config": "on"
          },
          {
            "Type": "cve",
            "Config": "on"
          },
          {
            "Type": "imageVulClean",
            "Config": "90"
          },
          {
            "Type": "cms",
            "Config": "on"
          },
          {
            "Type": "scanMode",
            "Config": "all"
          },
          {
            "Type": "sys",
            "Config": "on"
          },
          {
            "Type": "emg",
            "Config": "on"
          }
        ],
        "RequestId": "C78D1769-D3F3-5395-A6D1-08F547F1FDB3"
      },
      {
        "TotalCount": 8,
        "TargetConfigs": [
          {
            "Type": "app",
            "Config": "on"
          },
          {
            "Type": "yum",
            "Config": "on"
          },
          {
            "Type": "cve",
            "Config": "off"
          },
          {
            "Type": "imageVulClean",
            "Config": "90"
          },
          {
            "Type": "cms",
            "Config": "off"
          },
          {
            "Type": "scanMode",
            "Config": "all"
          },
          {
            "Type": "sys",
            "Config": "on"
          },
          {
            "Type": "emg",
            "Config": "on"
          }
        ],
        "RequestId": "C78D1769-D3F3-5395-A6D1-08F547F1FDB3"
      }
];

const createCache = (describeVulConfig, describeVulConfigErr) => {
    return {
        tds: {
            DescribeVulConfig: {
                'cn-hangzhou': {
                    data: describeVulConfig,
                    err: describeVulConfigErr
                },
            }
        }
    };
};

describe('vulnerabilityScanEnabled', function () {
    describe('run', function () {
        it('should FAIL if Vulnerability scan is not enabled on all servers', function (done) {
            const cache = createCache(describeVulConfig[1]);
            vulnerabilityScanEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Vulnerability scan is not enabled for all servers');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should PASS if Vulnerability scan is enabled on all servers', function (done) {
            const cache = createCache(describeVulConfig[0]);
            vulnerabilityScanEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Vulnerability scan is enabled for all servers');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no vulnerabity config found ', function (done) {
            const cache = createCache([]);
            vulnerabilityScanEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No TDS vulnerability config');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query ', function (done) {
            const cache = createCache([], { err: 'Unable to query TDS vul config' });
            vulnerabilityScanEnabled.run(cache, { china: true }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query TDS vulnerability config: ');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    });
});