var expect = require('chai').expect;
const noUserIamPolicies = require('./noUserIamPolicies');

const listUsers = [
    {
        "Path": "/",
        "UserName": "cloudsploit",
        "UserId": "AIDAYE32SRU57PAYVNPEI",
        "Arn": "arn:aws:iam::111122223333:user/cloudsploit",
        "CreateDate": "2020-09-12T16:58:32Z",
        "PasswordLastUsed": "2020-11-14T18:51:16Z"
    }
];

const listUserPolicies = [
    {
        "PolicyNames": []
    },
    {
        "PolicyNames": [
            "CustomIAMFull",
            "CutomIAMLimited"
        ]
    },
];

const listAttachedUserPolicies = [
    
    {
        "AttachedPolicies": []
    },
    {
        "AttachedPolicies": [
            {
                "PolicyName": "IAMFullAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/IAMFullAccess"
            },
            {
                "PolicyName": "AmazonS3FullAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"
            },
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            {
                "PolicyName": "IAMUserChangePassword",
                "PolicyArn": "arn:aws:iam::aws:policy/IAMUserChangePassword"
            },
            {
                "PolicyName": "AWSBillingReadOnlyAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"
            }
        ]
    }
];

const createCache = (users, attachedPolicies, userPolicies) => {
    if(users && users.length && users[0].UserName) var username = users[0].UserName;

    return {
        iam:{
            listUsers: {
                'us-east-1': {
                    data: users
                },
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: attachedPolicies
                    },
                },
            },
            listUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: userPolicies
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {

    return {
        iam:{
            listUsers: {
                'us-east-1': {
                    err: {
                        message: 'error list users'
                    },
                },
            },
        },
    };
};

const createAttachedPoliciesErrorCache = (users) => {
    if(users && users.length && users[0].UserName) var username = users[0].UserName;

    return {
        iam:{
            listUsers: {
                'us-east-1': {
                    data: users
                },
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [username]: {
                        err: {
                            message: 'error listing attached user policies'
                        },
                    },
                },
            },
            listUserPolicies: {
                'us-east-1': {
                    [username]: {
                        err: {
                            message: 'error listing user policies'
                        },
                    },
                },
            },
        },
    };
};

const createUserPoliciesErrorCache = (users, attachedPolicies) => {
    if(users && users.length && users[0].UserName) var username = users[0].UserName;

    return {
        iam:{
            listUsers: {
                'us-east-1': {
                    data: users
                },
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: attachedPolicies
                    }
                },
            },
            listUserPolicies: {
                'us-east-1': {
                    [username]: {
                        err: {
                            message: 'error listing user policies'
                        },
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam:{
            listUsers: {
                'us-east-1': null
            },
            listAttachedUserPolicies: {
                'us-east-1': null
            },
            listUserPolicies: {
                'us-east-1': null
            },
        },
    };
};

describe('noUserIamPolicies', function () {
    describe('run', function () {
        it('should PASS if user is using attached or inline policies', function (done) {
            const cache = createCache([listUsers[0]], listAttachedUserPolicies[0], listUserPolicies[0]);
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if user is using attached or inline policies', function (done) {
            const cache = createCache([listUsers[0]], listAttachedUserPolicies[1], listUserPolicies[1]);
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no user accounts found', function (done) {
            const cache = createCache([]);
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list users', function (done) {
            const cache = createErrorCache();
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached policies for user', function (done) {
            const cache = createAttachedPoliciesErrorCache([listUsers[0]]);
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list user policies', function (done) {
            const cache = createUserPoliciesErrorCache([listUsers[0]], listAttachedUserPolicies[0]);
            noUserIamPolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
    });
});
