var expect = require('chai').expect;
const iamUserWithoutPermissions = require('./iamUserWithoutPermissions');

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

const groups = [
    {
        "Path": "/",
        "GroupName": "akhtar-gr-15",
        "GroupId": "AGPAYE32SRU5WTVWZJGNX",
        "Arn": "arn:aws:iam::123456654321:group/akhtar-gr-15",
        "CreateDate": "2020-08-30T14:24:48.000Z"
      },
      {
        "Path": "/",
        "GroupName": "akhtar-gr3-15",
        "GroupId": "AGPAYE32SRU56LRFN4U55",
        "Arn": "arn:aws:iam::123456654321:group/akhtar-gr3-15",
        "CreateDate": "2020-08-30T15:06:01.000Z"
      }
];
const groupsForUsers = {
    Groups: [ {"GroupName": "akhtar-gr-15"}]
}
const groupPolicies = [
    {
        ResponseMetadata: { RequestId: 'ac47dbfc-6333-4840-8500-2ffb616f03d4' },
        PolicyNames: [
            'policygen-akhtar-gr-15-202008301932',
            'policygen-akhtar-gr-15-202008302019'
            ],
        IsTruncated: false
    },
    {
        ResponseMetadata: { RequestId: '485a4202-06ef-4e8b-9661-ed4d1dd286d3' },
        PolicyNames: [
         
        ],
        IsTruncated: false
    }
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

const createCache = (users, listUserPolicies, attachedUserPolicies, groups, groupsForUsers, getPolicy, groupAttachedPolicies ) => {
    if (users && users.length && users[0].UserName) var username = users[0].UserName;
    if (groups && groups.length) var groupName = groups[0].GroupName;

    return {
        iam:{
            listUsers: {
                'us-east-1': {
                    data: users
                },
            },
            listUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: listUserPolicies
                    },
                },
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: attachedUserPolicies
                    },
                },
            },
            listGroups: {
                'us-east-1': {
                    data: groups,
                },
            },
            listGroupsForUser: {
                'us-east-1': {
                    [username]: {
                        data: groupsForUsers
                    }
                }
            },
            listGroupPolicies: {
                'us-east-1': {
                    [groupName]: {
                        data: getPolicy
                    }
                }
            },
            
            listAttachedGroupPolicies: {
                'us-east-1': {
                    [groupName]: {
                        data: groupAttachedPolicies
                    }
                }
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


describe('iamUserWithoutPermissions', function () {
    describe('run', function () {
       it('should PASS if no IAM users found', function (done) {
            const cache = createCache([]);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if uanble to list IAM users', function (done) {
            const cache = createErrorCache();
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if uanble to list IAM user policies', function (done) {
            const cache = createCache(listUsers, null, listAttachedUserPolicies, groups);
            
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
         });
        it('should UNKNOWN if uanble to list IAM attached user policies', function (done) {
            const cache = createCache(listUsers, listUserPolicies, null);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        it('should UNKNOWN if uanble to list group policies', function (done) {
            const cache = createCache(listUsers, listUserPolicies, listAttachedUserPolicies, groups, groupsForUsers, null, groupPolicies);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if uanble to list group attached policies', function (done) {
            const cache = createCache(listUsers, listUserPolicies, listAttachedUserPolicies, groups, groupsForUsers, groupPolicies, null);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if user has permissions', function (done) {
            const cache = createCache(listUsers, listUserPolicies[1], listAttachedUserPolicies[1], groups,  {Groups: []}, groupPolicies[0]);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).includes('IAM user has permissions');
                done();
            });
        });
        it('should FAIL if user does not have permissions', function (done) {
            const cache = createCache(listUsers, listUserPolicies[0], listAttachedUserPolicies[0], groups,  {Groups: []}, groupPolicies[0]);
            iamUserWithoutPermissions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).includes('IAM user does not have any permissions');
                done();
            });
        });
    });
});
