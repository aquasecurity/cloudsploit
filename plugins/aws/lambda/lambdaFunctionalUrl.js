var async = require("async");
var helpers = require("../../../helpers/aws");

module.exports = {
  title: "Lambda Function URL Public Check",
  category: "Lambda",
  domain: "Serverless",
  severity: "High",
  description:"Checks if any Lambda function has a publicly accessible Function URL.",
  more_info:
    "Function URLs without authentication (AuthType=NONE) are publicly invokable and may pose security risks.",
  link: "https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html",
  recommended_action:
    "Set AuthType to AWS_IAM or restrict access via resource-based policy.",
  apis: ["Lambda:listFunctions", "Lambda:getFunctionUrlConfig"],
  realtime_triggers: [
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
  ],

  run: function (cache, settings, callback) {
    var results = [];
    var source = {};
    var regions = helpers.regions(settings);
    async.each(
      regions.lambda,
      function (region, rcb) {
        var listFunctions = helpers.addSource(cache, source, [
          "lambda",
          "listFunctions",
          region,
        ]);
        if (!listFunctions) return rcb();
        if (listFunctions.err || !listFunctions.data) {
          helpers.addResult(
            results,
            3,
            `Unable to query for Lambda functions:${helpers.addError(listFunctions)}`,
            region,
          );
          return rcb();
        }
        if (!listFunctions.data.length) {
          helpers.addResult(results, 0, "No Lambda functions found", region);
          return rcb();
        }

        async.each(listFunctions.data, function (lambdaFunc, fcb) {
          if (!lambdaFunc.FunctionArn) return fcb();
          var resource = lambdaFunc.FunctionArn;

          var functionUrlConfig = helpers.addSource(cache, source, [
            "lambda",
            "getFunctionUrlConfig",
            region,
            lambdaFunc.FunctionName,
          ]);
          if (!functionUrlConfig || functionUrlConfig.err) {
            helpers.addResult(
              results,
              0,
              "No Function URL configured",
              region,
              resource,
            );
            return fcb();
          }
          if (
            functionUrlConfig.data &&
            functionUrlConfig.data.AuthType === "NONE"
          ) {
            helpers.addResult(
              results,
              2,
              "Function URL is public (AuthType=NONE)",
              region,
              resource,
              functionUrlConfig.data.FunctionUrl,
            );
          } else if (
            functionUrlConfig.data &&
            functionUrlConfig.data.AuthType
          ) {
            helpers.addResult(
              results,
              0,
              `Function URL exists but is secure(AuthType=${functionUrlConfig.data.AuthType})`,
              region,
              resource,
              functionUrlConfig.data.FunctionUrl,
            );
          }
          fcb();
        });
        rcb();
      },
      function () {
        callback(null, results, source);
      },
    );
  },
};
