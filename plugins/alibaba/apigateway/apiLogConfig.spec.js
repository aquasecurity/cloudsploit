var expect = require('chai').expect;
var apiLogConfig = require('./apiLogConfig')

const describeLogConfig = {
    "SlsLogStore": "api-logstore",
    "SlsProject": "api-log",
    "LogType": "PROVIDER",
    "RegionId": "cn-hangzhou"
}

const createCache = logConfig => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': {
                    data: logConfig
                }
            }
        }
    }
}

const errorCache = () => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': {
                    err: 'Unable to describe APIs',
                }
            }
        }
    }
}

const nullCache = () => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': null
            }
        }
    }
}

describe('apiLogConfig', () => {
    describe('run', () => {       
         it('should PASS if API has log service configured', done => {
             const cache = createCache([describeLogConfig]);
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].message).to.include('APIs are configured to publish logs to Log Service');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
  
         it('should FAIL if API does not have log service configured', done => {
             const cache = createCache([{}]);
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('APIs are not configured to publish logs to Log Service');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should UNKNOWN if unable to describe log config', done => {
             const cache = errorCache();
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(3);
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should not return anything if response not received', done => {
             const cache = nullCache();
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(0);
                 done();
             });
         });
     })
 })
 