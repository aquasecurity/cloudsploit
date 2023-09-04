const expect = require('chai').expect;
const iamRolesHasTags = require('./iamRoleHasTags.js');

const listRoles = [
    { 
        "Path": "/",
        "RoleName": "aqua-cspm-security-remediator-rotator",
        "RoleId": "AROARPGOCGXSYQSXS37BT",
        "Arn": "arn:aws:iam::000000001111111:role/aqua-cspm-security-remediator-rotator",
        "CreateDate": "2022-09-21T09:56:11+00:00",
    },
    {
        "Path": "/",
        "RoleName": "s3AdminAccess",
        "RoleId": "AROARPGOCGXST7CLXIBTZ",
        "Arn": "arn:aws:iam::0000000001111111:role/s3AdminAccess",
        "CreateDate": "2022-09-07T13:41:36+00:00",
    }
];
 
const getRole= [
    {
        'Role':{
            "Path": "/",
            "RoleName": "aqua-cspm-security-remediator-rotator",
            "RoleId": "AROARPGOCGXSYQSXS37BT",
            "Arn": "arn:aws:iam::000000001111111:role/aqua-cspm-security-remediator-rotator",
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ],
        }  
    },  
    {  
        "Role": {
            "Path": "/",
            "RoleName": "s3AdminAccess",
            "RoleId": "AROARPGOCGXST7CLXIBTZ",
            "Arn": "arn:aws:iam::0000000001111111:role/s3AdminAccess",
        
        }
    }

]
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

describe('iamRolesHasTags', function () {
    describe('run', function () {
        it('Should PASS if IAM role has tags', function (done) {
            const cache = createCache([listRoles[0]],getRole[0]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('IAM Role has tags');
                done();
            });
        });

        it('Should FAIL if IAM role does not have tags', function (done) {
            const cache = createCache([listRoles[1]],getRole[1]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('IAM Role does not have tags');
                done();
            });
        });
        
        it('Should UNKNOWN if error in listing IAM user', function (done) {
            const cache = createErrorCache();
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('Should PASS if no IAM role found', function (done) {
            const cache = createCache([]);
            iamRolesHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});