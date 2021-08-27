var expect = require('chai').expect;
var apiProtocol = require('./apiProtocol')

const describeApis = {
    "GroupName": "test_group",
    "CreatedTime": "2021-08-24T05:47:32Z",
    "ModifiedTime": "2021-08-24T05:47:32Z",
    "ApiName": "test_api",
    "Visibility": "PRIVATE",
    "RegionId": "cn-hangzhou",
    "ApiId": "69567aca1ff14efe8b864fb1a6f58f32",
    "GroupId": "db81d7d3fd794d3db5a4642afb408fa7"
}

const describeApi = [
    {
        "GroupName": "test_group",
        "CreatedTime": "2021-08-24T05:47:32Z",
        "ForceNonceCheck": false,
        "DeployedInfos": {
            "DeployedInfo": [
                {
                    "StageName": "RELEASE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "PRE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "TEST",
                    "EffectiveVersion": "20210824134753641",
                    "DeployedStatus": "DEPLOYED"
                }
            ]
        },
        "ResultDescriptions": {
            "ResultDescription": []
        },
        "AuthType": "APP",
        "RequestConfig": {
            "RequestPath": "/getInfo",
            "RequestMode": "MAPPING",
            "RequestProtocol": "HTTPS",
            "RequestHttpMethod": "GET",
            "PostBodyDescription": "",
            "BodyFormat": ""
        },
        "GroupId": "db81d7d3fd794d3db5a4642afb408fa7",
        "Visibility": "PRIVATE",
        "RegionId": "cn-hangzhou",
        "ServiceParameters": {
            "ServiceParameter": []
        },
        "ApiId": "69567aca1ff14efe8b864fb1a6f58f32"
    },
    {
        "GroupName": "test_group",
        "CreatedTime": "2021-08-24T05:47:32Z",
        "ForceNonceCheck": false,
        "DeployedInfos": {
            "DeployedInfo": [
                {
                    "StageName": "RELEASE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "PRE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "TEST",
                    "EffectiveVersion": "20210824134753641",
                    "DeployedStatus": "DEPLOYED"
                }
            ]
        },
        "ResultDescriptions": {
            "ResultDescription": []
        },
        "AuthType": "APP",
        "RequestConfig": {
            "RequestPath": "/getInfo",
            "RequestMode": "MAPPING",
            "RequestProtocol": "HTTP",
            "RequestHttpMethod": "GET",
            "PostBodyDescription": "",
            "BodyFormat": ""
        },
        "GroupId": "db81d7d3fd794d3db5a4642afb408fa7",
        "Visibility": "PRIVATE",
        "RegionId": "cn-hangzhou",
        "ServiceParameters": {
            "ServiceParameter": []
        },
        "ApiId": "69567aca1ff14efe8b864fb1a6f58f32"
    },
    {
        "GroupName": "test_group",
        "CreatedTime": "2021-08-24T05:47:32Z",
        "ForceNonceCheck": false,
        "DeployedInfos": {
            "DeployedInfo": [
                {
                    "StageName": "RELEASE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "PRE",
                    "DeployedStatus": "NONDEPLOYED"
                },
                {
                    "StageName": "TEST",
                    "EffectiveVersion": "20210824134753641",
                    "DeployedStatus": "DEPLOYED"
                }
            ]
        },
        "ResultDescriptions": {
            "ResultDescription": []
        },
        "AuthType": "APP",
        "GroupId": "db81d7d3fd794d3db5a4642afb408fa7",
        "Visibility": "PRIVATE",
        "RegionId": "cn-hangzhou",
        "ServiceParameters": {
            "ServiceParameter": []
        },
        "ApiId": "69567aca1ff14efe8b864fb1a6f58f32"
    }
    
]

const createCache = (describeApis, describeApi) => {
    const apiKey = (describeApis && describeApis.length && describeApis[0].ApiId) ? describeApis[0].ApiId : null;
    return {
        apigateway: {
            DescribeApis: {
                'cn-hangzhou': {
                    data: describeApis,
                }
            },
            DescribeApi: {
                'cn-hangzhou': {
                    [apiKey]: {
                        data: describeApi,
                    }
                }
            }
        }
    }
}
const errorCache = () => {
    return {
        apigateway: {
            DescribeApis: {
                'cn-hangzhou': {
                    err: 'Unable to describe APIs',
                }
            },
            DescribeApi: {
                'cn-hangzhou': {
                    err: 'Unable to describe API',
                }
            }
        }
    }
}

const nullCache = () => {
    return {
        apigateway: {
            DescribeApis: {
                'cn-hangzhou': null
            },
            DescribeApi: {
                'cn-hangzhou': null
            }
        }
    }
}

describe('apiProtocol', () => {
   describe('run', () => {       
        it('should PASS if API has HTTPS protocol configured', done => {
            const cache = createCache([describeApis], describeApi[0]);
            apiProtocol.run(cache, {}, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('API has HTTPS protocol configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if API does not HTTPS protocol configured', done => {
            const cache = createCache([describeApis], describeApi[1]);
            apiProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API does not have HTTPS protocol configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if API response does not have RequestConfig property', done => {
            const cache = createCache([describeApis], describeApi[2]);
            apiProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API does not have HTTPS protocol configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no APIs are found', done => {
            const cache = createCache({}, {});
            apiProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No APIs found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to describe APIs', done => {
            const cache = errorCache();
            apiProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should not return anything if response not received', done => {
            const cache = nullCache();
            apiProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    })
})
