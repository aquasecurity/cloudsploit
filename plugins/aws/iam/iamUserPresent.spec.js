const expect = require('chai').expect;
const iamUserPresent = require('./iamUserPresent.js');

const listUsers = [
    {
        UserName: 'test1',
        UserId: 'AIDAYE32SRU545SJ5O6AI',
        Arn: 'arn:aws:iam::000111222333:user/test1',
        CreateDate: '2021-09-23T10:58:24.000Z',
        PasswordLastUsed: '2021-10-04T13:02:00.000Z',
        Tags: []
    }   
];

const createCache = (listUsers) => {
    var usersName = (listUsers && listUsers.length) ? listUsers[0].usersName : null; 
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers,
                },
            },
           
        }
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

const createNullCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': null,
            },
        },
    };
};

describe('iamUserPresent', function () {
    describe('run', function () {
        it('should pass if users are present', function (done) {
            const cache = createCache([listUsers[0]]);
            iamUserPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no IAM user(s) are present and root account is being used', function (done) {
            const cache = createCache([]);
            iamUserPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
   
    });
});
