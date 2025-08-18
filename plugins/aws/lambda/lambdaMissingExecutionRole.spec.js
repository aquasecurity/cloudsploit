const expect = require('chai').expect;
const lambda = require('./lambdaMissingExecutionRole'); // your plugin

const listFunctions = [
  {
    FunctionName: 'test-lambda',
    FunctionArn: 'arn:aws:lambda:us-east-1:000011112222:function:test-lambda',
  },
  {
    FunctionName: 'func-no-role',
    FunctionArn: 'arn:aws:lambda:us-east-1:000011112222:function:func-no-role',
  },
  {
    FunctionName: 'func1',
    FunctionArn: 'arn:aws:lambda:us-east-1:000011112222:function:func1',
  },
];

function createCache(listFunctionsData, getFunctionData = {}, getRoleData = {}) {
  return {
    lambda: {
      listFunctions: {
        'us-east-1': {
          err: null,
          data: listFunctionsData,
        },
      },
      getFunction: {
        'us-east-1': getFunctionData,
      },
    },
    iam: {
      getRole: {
        'us-east-1': getRoleData,
      },
    },
  };
}

describe('Lambda Missing Execution Role Plugin', function () {
  it('should FAIL if unable to list Lambda functions', function (done) {
    const cache = {
      lambda: {
        listFunctions: {
          'us-east-1': { err: 'API failure', data: null },
        },
      },
    };

    lambda.run(cache, {}, (err, results) => {
      expect(err).to.be.null;
      expect(results).to.have.lengthOf(1);
      expect(results[0].status).to.equal(3);
      expect(results[0].message).to.include('Unable to query for Lambda functions');
      done();
    });
  });

  it('should PASS if no Lambda functions found', function (done) {
    const cache = createCache([]);

    lambda.run(cache, {}, (err, results) => {
      expect(err).to.be.null;
      expect(results).to.have.lengthOf(1);
      expect(results[0].status).to.equal(0);
      expect(results[0].message).to.include('No Lambda functions found');
      done();
    });
  });

  it('should FAIL if Lambda function has no execution role assigned', function (done) {
    const cache = createCache(
      [listFunctions[1]],
      {
        'func-no-role': { err: null, data: { Configuration: { Role: null } } },
      }
    );

    lambda.run(cache, {}, (err, results) => {
      expect(err).to.be.null;
      const found = results.some((r) => r.message.includes('no execution role assigned'));
      expect(found).to.be.true;
      done();
    });
  });

  it('should FAIL if execution role does not exist in IAM', function (done) {
    const cache = createCache(
      [listFunctions[2]],
      {
        func1: {
          err: null,
          data: {
            Configuration: {
              Role: 'arn:aws:iam::123456789012:role/nonexistent-role',
            },
          },
        },
      },
      {
        'nonexistent-role': { err: 'Role not found', data: null },
      }
    );

    lambda.run(cache, {}, (err, results) => {
      expect(err).to.be.null;
      const found = results.some((r) => r.message.includes('Execution role does not exist'));
      expect(found).to.be.true;
      done();
    });
  });

  it('should PASS if Lambda has a execution role and also exist in IAM', function (done) {
    const cache = createCache(
      [listFunctions[2]],
      {
        func1: {
          err: null,
          data: {
            Configuration: {
              Role: 'arn:aws:iam::123456789012:role/existing-role',
            },
          },
        },
      },
      {
        'existing-role': { err: null, data: { Role: { RoleName: 'existing-role' } } },
      }
    );

    lambda.run(cache, {}, (err, results) => {
      expect(err).to.be.null;
      const found = results.some((r) => r.message.includes('valid execution role'));
      expect(found).to.be.true;
      done();
    });
  });
});
