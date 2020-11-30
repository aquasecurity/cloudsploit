const expect = require('chai').expect;
const iamUserUnauthorizedToEdit = require('./iamUserUnauthorizedToEdit');
const helpers = require('../../../helpers/aws');

const listUsers = [
    {
        "Path": "/",
        "UserName": "test-cp1",
        "UserId": "IHCTGF32SRU57PAYVNPEI",
        "Arn": "arn:aws:iam::123456654321:user/test-cp1",
        "CreateDate": "2020-09-12T16:58:32.000Z",
        "PasswordLastUsed": "2020-09-20T04:19:18.000Z",
        "Tags": []
    },
    {
        "Path": "/",
        "UserName": "test-cp",
        "UserId": "AIDAYE32SRU57PAYVNPEI",
        "Arn": "arn:aws:iam::123456654321:user/test-cp",
        "CreateDate": "2020-09-12T16:58:32.000Z",
        "PasswordLastUsed": "2020-09-20T04:19:18.000Z",
        "Tags": []
    }
];

const listUserPolicies = [
        "CustomIAMFull",
        "CustomIAMLimited"
];

const listAttachedUserPolicies = [
    {
        "PolicyName": "IAMFullAccess",
        "PolicyArn": "arn:aws:iam::aws:policy/IAMFullAccess"
    },
    {
        "PolicyName": "AdministratorAccess",
        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    {
        "PolicyName": "IAMUserChangePassword",
        "PolicyArn": "arn:aws:iam::aws:policy/IAMUserChangePassword"
    }
];

const getUserPolicy = [
    {
        "UserName": "test-cp",
        "PolicyName": "customIAMFull",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*"
                }
            ]
        }
    },
    {
        "UserName": "test-cp1",
        "PolicyName": "CustomIAMLimited",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateGroup",
                        "iam:CreateRole"
                    ],
                    "Resource": "*"
                }
            ]
        }
    }
];

const listGroups = [
    {
        "Path": "/",
        "GroupName": "group1",
        "GroupId": "AGPAYE32SRU5VIDOFGQPO",
        "Arn": "arn:aws:iam::123456654321:group/group1",
        "CreateDate": "2020-10-24T14:50:04.000Z"
    }
];

const createCache = (listUsers, listPolicies, attachedPolicies, getPolicy, listGroups) => {
    var userName = (listUsers && listUsers.length) ? listUsers[0].UserName : null;
    var groupName = (listGroups && listGroups.length) ? listGroups[0].GroupName : null;
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers
                }
            },
            listUserPolicies: {
                'us-east-1': {
                    [userName]: {
                        data: {
                            PolicyNames: listPolicies
                        }
                    }
                }
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [userName]: {
                        data: {
                            AttachedPolicies: attachedPolicies
                        }
                    }
                }
            },
            getUserPolicy: {
                'us-east-1': {
                    [userName]: {
                        data: getPolicy
                    }
                }
            },
            listGroups: {
                'us-east-1': {
                    data: listGroups
                }
            },
            listGroupsForUser: {
                'us-east-1': {
                    [userName]: {
                        data: {
                            Groups: listGroups
                        }
                    }
                }
            },
            listAttachedGroupPolicies: {
                'us-east-1': {
                    [groupName]: {
                        data: {
                            AttachedPolicies: attachedPolicies
                        }
                    }
                }
            },
            getGroupPolicy: {
                'us-east-1': {
                    [groupName]: {
                        data: getPolicy
                    }
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': null,
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM users'
                    },
                },
            },
        },
    };
};

const createListPoliciesErrorCache = (listUsers) => {
    var userName = (listUsers && listUsers.length) ? listUsers[0].UserName : null;
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers
                }
            },
            listUserPolicies: {
                'us-east-1': {
                    [userName]: {
                        err: {
                            message: 'error listing user policies'
                        }
                    }
                },
            },
        },
    };
};

describe('iamUserUnauthorizedToEdit', function () {
    describe('run', function () {

        it('should PASS if the IAM user does not have edit IAM access policies', function (done) {
            const cache = createCache([listUsers[0]], [listUserPolicies[1]], [listAttachedUserPolicies[2]], getUserPolicy[0], [listGroups[0]]);
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if the IAM user is authorized to edit IAM access policies', function (done) {
            const cache = createCache([listUsers[0]], [listUserPolicies[0]], [listAttachedUserPolicies[1]], getUserPolicy[1]);
            const settings = {
                iam_authorized_user_arns: 'arn:aws:iam::123456654321:user/test-cp1'
            }
            iamUserUnauthorizedToEdit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if the IAM user is not authorized to have edit access policies permission', function (done) {
            const cache = createCache([listUsers[1]], [listUserPolicies[0]], [listAttachedUserPolicies[1]], getUserPolicy[0]);
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no IAM users found', function (done) {
            const cache = createCache([]);
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if uanble to list IAM users', function (done) {
            const cache = createErrorCache();
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if uanble to list IAM user policies', function (done) {
            const cache = createListPoliciesErrorCache(listUsers);
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list IAM users response not found', function (done) {
            const cache = createNullCache();
            iamUserUnauthorizedToEdit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});