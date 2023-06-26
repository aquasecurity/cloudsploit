var assert = require('assert');
var expect = require('chai').expect;
var iamRoleLastUsed = require('./iamRoleLastUsed');

const listRoles = [
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
    },
    {
        "Path": "/",
        "RoleName": "SampleRole4",
        "RoleId": "ABCDEFG",
        "Arn": "arn:aws:iam::01234567819101:role/SampleRole4",
        "CreateDate": "2019-11-19T14:52:01.000Z",
        "AssumeRolePolicyDocument": ""
    }
];
 
const getRole= [
    {
        "Role": {
            "Path": "/",
            "RoleName": "SampleRole1",
            "RoleId": "ABCDEFG",
            "Arn": "arn:aws:iam::01234567819101:role/SampleRole1",
            "CreateDate": "2019-11-19T14:52:01.000Z",
            "AssumeRolePolicyDocument": "",
            "RoleLastUsed": {},
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ]
        }
    },
    {
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
    },
    {
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
    },
    {
        "Role": {
            "Path": "/",
            "RoleName": "SampleRole4",
            "RoleId": "ABCDEFG",
            "Arn": "arn:aws:iam::01234567819101:role/SampleRole3",
            "CreateDate": "2019-11-19T14:52:01.000Z",
            "AssumeRolePolicyDocument": "",
            "RoleLastUsed": {
                "LastUsedDate": "2019-05-18T14:42:29.000Z",
                "Region": "us-east-1"
            },
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ]
        }
    }
];

const createCache = (listRoles,getRole) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null; 
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles,
                    err: null
                },
            },
            getRole: {
                'us-east-1': {
                    [roleName]:{   
                        data: getRole,
                        err: null    
                    }              
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM Roles'
                    },
                },
            },
        },
    };
};

describe('iamRoleLastUsed', function() {
    describe('run', function() {
        it('should FAIL when no last used date present', function(done) {
            const cache = createCache([listRoles[0]],getRole[0]);
            iamRoleLastUsed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has not been used');
                done();
            });
        });

        it('should PASS when last used date is recent', function(done) {
            const cache = createCache([listRoles[1]],getRole[1]);
            iamRoleLastUsed.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('IAM role was last used');
                done();
            });
        });

        it('should FAIL when last used date is old', function(done) {
            const cache = createCache([listRoles[2]],getRole[2]);
            iamRoleLastUsed.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role with specific regex is ignored',function(done) {
            const cache = createCache([listRoles[3]],getRole[3]);
            iamRoleLastUsed.run(cache, {iam_role_policies_ignore_tag:'app_name:Aqua CSPM'}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
