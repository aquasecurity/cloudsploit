var assert = require('assert');
var expect = require('chai').expect;
var iamRoleLastUsed = require('./iamRoleLastUsed');

const cache = {
    "iam": {
        "listRoles": {
            "us-east-1": {
                "data": [
                    {
                        "Path": "/",
                        "RoleName": "SampleRole1",
                        "RoleId": "ABCDEFG",
                        "Arn": "arn:aws:iam::01234567819101:role/SampleRole1",
                        "CreateDate": "2019-11-19T14:52:01.000Z",
                        "AssumeRolePolicyDocument": ""
                    },
                    {
                        "Path": "/",
                        "RoleName": "SampleRole2",
                        "RoleId": "ABCDEFG",
                        "Arn": "arn:aws:iam::01234567819101:role/SampleRole2",
                        "CreateDate": "2019-11-19T14:52:01.000Z",
                        "AssumeRolePolicyDocument": ""
                    },
                    {
                        "Path": "/",
                        "RoleName": "SampleRole3",
                        "RoleId": "ABCDEFG",
                        "Arn": "arn:aws:iam::01234567819101:role/SampleRole3",
                        "CreateDate": "2019-11-19T14:52:01.000Z",
                        "AssumeRolePolicyDocument": ""
                    }
                ]
            }
        },
        "getRole": {
            "us-east-1": {
                "SampleRole1": {
                    "data": {
                        "Role": {
                            "Path": "/",
                            "RoleName": "SampleRole1",
                            "RoleId": "ABCDEFG",
                            "Arn": "arn:aws:iam::01234567819101:role/SampleRole1",
                            "CreateDate": "2019-11-19T14:52:01.000Z",
                            "AssumeRolePolicyDocument": "",
                            "RoleLastUsed": {}
                        }
                    }
                },
                "SampleRole2": {
                    "data": {
                        "Role": {
                            "Path": "/",
                            "RoleName": "SampleRole2",
                            "RoleId": "ABCDEFG",
                            "Arn": "arn:aws:iam::01234567819101:role/SampleRole2",
                            "CreateDate": "2019-11-19T14:52:01.000Z",
                            "AssumeRolePolicyDocument": "",
                            "RoleLastUsed": {
                                "LastUsedDate": new Date(),
                                "Region": "us-east-1"
                            }
                        }
                    }
                },
                "SampleRole3": {
                    "data": {
                        "Role": {
                            "Path": "/",
                            "RoleName": "SampleRole3",
                            "RoleId": "ABCDEFG",
                            "Arn": "arn:aws:iam::01234567819101:role/SampleRole3",
                            "CreateDate": "2019-11-19T14:52:01.000Z",
                            "AssumeRolePolicyDocument": "",
                            "RoleLastUsed": {
                                "LastUsedDate": "2019-05-18T14:42:29.000Z",
                                "Region": "us-east-1"
                            }
                        }
                    }
                },
            }
        }
    }
}


describe('iamRoleLastUsed', function() {
    describe('run', function() {
        it('should FAIL when no last used date present', function(done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            }

            iamRoleLastUsed.run(cache, {}, callback)
        })

        it('should PASS when last used date is recent', function(done) {
            const callback = (err, results) => {
                expect(results[1].status).to.equal(0)
                done()
            }

            iamRoleLastUsed.run(cache, {}, callback)
        })

        it('should FAIL when last used date is old', function(done) {
            const callback = (err, results) => {
                expect(results[2].status).to.equal(2)
                done()
            }

            iamRoleLastUsed.run(cache, {}, callback)
        })
    })
})
