const expect = require("chai").expect;
const lambdaFunctionalUrl = require("./lambdaFunctionalUrl");

const listFunctions = [
  {
    FunctionName: "public-lambda",
    FunctionArn: "arn:aws:lambda:us-east-1:000011112222:function:public-lambda",
    FunctionUrlConfig: { AuthType: "NONE" },
  },
  {
    FunctionName: "private-lambda",
    FunctionArn:
      "arn:aws:lambda:us-east-1:000011112222:function:private-lambda",
    FunctionUrlConfig: { AuthType: "AWS_IAM" },
  },
];

const createCache = (lambdaList) => {
  const cache = {
    lambda: {
      listFunctions: { "us-east-1": { data: lambdaList } },
      getFunctionUrlConfig: { "us-east-1": {} },
    },
  };

  lambdaList.forEach((func) => {
    cache.lambda.getFunctionUrlConfig["us-east-1"][func.FunctionName] = {
      data: func.FunctionUrlConfig,
    };
  });

  return cache;
};

describe("lambdaFunctionalUrl", function () {
  describe("run", function () {
    it("should FAIL if lambda URL is public", function (done) {
      const cache = createCache([listFunctions[0]]);
      lambdaFunctionalUrl.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].resource).to.equal(listFunctions[0].FunctionArn);
        done();
      });
    });
    it("should PASS if lambda URL is private", function (done) {
      const cache = createCache([listFunctions[1]]);
      lambdaFunctionalUrl.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        done();
      });
    });
    it("should PASS if no lambda functions found", function (done) {
      const cache = createCache([]);
      lambdaFunctionalUrl.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        done();
      });
    });
    it("should UNKNOWN if unable to list Lambda functions", function (done) {
      const cache = {
        lambda: {
          listFunctions: { "us-east-1": { err: { message: "AWS error" } } },
        },
      };
      lambdaFunctionalUrl.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        done();
      });
    });
  });
});
