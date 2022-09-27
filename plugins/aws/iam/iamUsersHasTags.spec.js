const expect = require('chai').expect;
const iamUserHasTags = require('./iamUsersHasTags.js');

const listUsers = [
    {
        UserName: 'test1',
        UserId: 'AIDAYE32SRU545SJ5O6AI',
        Arn: 'arn:aws:iam::000111222333:user/test1',
        CreateDate: '2021-09-23T10:58:24.000Z',
        PasswordLastUsed: '2021-10-04T13:02:00.000Z',
        Tags: []
    }, 
    {
        UserName: 'test2',
        UserId: 'AIDAYE32SRU545SJ5O6AI',
        Arn: 'arn:aws:iam::000111222333:user/test2',
        CreateDate: '2021-09-23T10:58:24.000Z',
        PasswordLastUsed: '2021-10-04T13:02:00.000Z',
        Tags: [{"Name" : "tag", "Value": "val"}]
    }   
];

const createCache = (listUsers) => {
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers,
                    err: null
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

describe('iamUserHasTags', function () {
    describe('run', function () {
        it('should give passing result if iam user has tags', function (done) {
            const cache = createCache([listUsers[1]]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should give failing result if iam user has no tags', function (done) {
            const cache = createCache([listUsers[0]]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should give unknown result if error in lsiting iam users', function (done) {
            const cache = createErrorCache();
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should give passing result if no iam user found', function (done) {
            const cache = createCache([]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});
