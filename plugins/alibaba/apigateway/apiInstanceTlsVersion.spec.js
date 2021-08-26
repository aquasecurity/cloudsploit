var expect = require('chai').expect;
var apiInstanceTlsVersion = require('./apiInstanceTlsVersion')

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

const describeApiGroup = [
    {
        "GroupName": "test_group",
        "Description": "",
        "CreatedTime": "2021-08-26T07:03:22Z",
        "HttpsPolicy": "HTTPS2_TLS1_0",
        "BasePath": "/trs",
        "VpcDomain": "",
        "SubDomain": "da12e54692c2435ab4ef3b4d0274ea93-cn-hangzhou.alicloudapi.com",
        "ModifiedTime": "2021-08-26T07:03:22Z",
        "CustomDomains": {
            "DomainItem": []
        },
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "Ipv6Status": "UNBIND",
        "RegionId": "cn-hangzhou"
    },
    {
        "GroupName": "test_group",
        "Description": "",
        "CreatedTime": "2021-08-26T07:03:22Z",
        "HttpsPolicy": "HTTPS1_TLS1_2",
        "BasePath": "/trs",
        "VpcDomain": "",
        "SubDomain": "da12e54692c2435ab4ef3b4d0274ea93-cn-hangzhou.alicloudapi.com",
        "ModifiedTime": "2021-08-26T07:03:22Z",
        "CustomDomains": {
            "DomainItem": []
        },
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "Ipv6Status": "UNBIND",
        "RegionId": "cn-hangzhou"
    },
    {
        "GroupName": "test_group",
        "Description": "",
        "CreatedTime": "2021-08-26T07:03:22Z",
        "BasePath": "/trs",
        "VpcDomain": "",
        "SubDomain": "da12e54692c2435ab4ef3b4d0274ea93-cn-hangzhou.alicloudapi.com",
        "ModifiedTime": "2021-08-26T07:03:22Z",
        "CustomDomains": {
            "DomainItem": []
        },
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "Ipv6Status": "UNBIND",
        "RegionId": "cn-hangzhou"
    }
]

const createCache = (describeApi, describeApiGroup) => {
    const groupId = (describeApi && describeApi[0].GroupId) ? describeApi[0].GroupId : null;
    return {
        apigateway: {
            DescribeApis: {
                'cn-hangzhou': {
                    data: describeApi
                }
            },
            DescribeApiGroup: {
                'cn-hangzhou': {
                    [groupId]: {
                        data: describeApiGroup
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
                    err: 'Unable to describe APIs'
                }
            },
            DescribeApiGroup: {
                'cn-hangzhou': {
                    ['id']: {
                        err: 'Unable to describe API group'
                    }
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
            DescribeApiGroup: {
                'cn-hangzhou': null
            }
        }
    }
}

describe('apiInstanceTlsVersion', () => {
    describe('run', () => {       
         it('should PASS if API has latest TLS version', done => {
             const cache = createCache([describeApis], describeApiGroup[0]);
             apiInstanceTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].message).to.include('API instance has latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
  
         it('should FAIL if API does not have latest TLS version', done => {
             const cache = createCache([describeApis], describeApiGroup[1]);
             apiInstanceTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('API instance does not have latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });

         it('should FAIL if API response does not have HttpsPolicy', done => {
             const cache = createCache([describeApis], describeApiGroup[2]);
             apiInstanceTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('API instance does not have latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should UNKNOWN if unable to describe apis', done => {
             const cache = errorCache();
             apiInstanceTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(3);
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should not return anything if response not received', done => {
             const cache = nullCache();
             apiInstanceTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(0);
                 done();
             });
         });
     })
 })
 