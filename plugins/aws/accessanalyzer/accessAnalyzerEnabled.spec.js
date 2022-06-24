var expect = require('chai').expect;;
var accessAnalyzerEnabled = require('./accessAnalyzerEnabled');

const listAnalyzers = [
    {
      "arn": "arn:aws:access-analyzer:us-east-1:111111111111:analyzer/ConsoleAnalyzer-NVirginia",
      "createdAt": "2021-07-26T11:09:04.000Z",
      "lastResourceAnalyzed": "arn:aws:iam::111111111111:role/aqua-cspm-security-scanner-AquaCSPMRole-1EQQWMHKF061P",
      "lastResourceAnalyzedAt": "2021-07-26T11:09:04.992Z",
      "name": "ConsoleAnalyzer-NVirginia",
      "status": "ACTIVE",
      "tags": {},
      "type": "ACCOUNT"
    },
    {
      "arn": "arn:aws:access-analyzer:us-east-1:111111111111:analyzer/ConsoleAnalyzer-NVirginia",
      "createdAt": "2021-07-26T11:09:04.000Z",
      "lastResourceAnalyzed": "arn:aws:iam::111111111111:role/aqua-cspm-security-scanner-AquaCSPMRole-1EQQWMHKF061P",
      "lastResourceAnalyzedAt": "2021-07-26T11:09:04.992Z",
      "name": "ConsoleAnalyzer-NVirginia",
      "status": "DISABLED",
      "tags": {},
      "type": "ACCOUNT"
    }
];

const createCache = (analyzers) => {
    return {
        accessanalyzer: {
            listAnalyzers: {
                "us-east-1": {
                    data: analyzers                },
            }
        }
    }
}

const createNullCache = () => {
    return {
        accessanalyzer: {
            listAnalyzers: {
                "us-east-1": {
                    data: null
                }
            }
        }
    }
}

describe('accessAnalyzerEnabled', () => {
    describe('run', () => {
        it('should PASS if Access Analyzer is enabled', () => {
            const cache = createCache([listAnalyzers[0]]);
            accessAnalyzerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });
        it('should FAIL if Access Analyzer is not enabled', () => {
            const cache = createCache([listAnalyzers[1]]);
            accessAnalyzerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });
        it('should FAIL if Access Analyzer not configured', () => {
            const cache = createCache([]);
            accessAnalyzerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });
        it('should UNKNOWN if unable to list Access analyzer', () => {
            const cache = createNullCache();
            accessAnalyzerEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
            })
        });
        it('should not return anything if list Access Analyzers response is not found', () => {
            accessAnalyzerEnabled.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});