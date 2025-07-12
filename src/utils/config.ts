import { Aws } from "aws-cdk-lib";
import * as fs from "fs";
import * as yaml from "js-yaml";
import * as path from "path";

export interface AppConfig {
  readonly adminEmail: string;
  readonly appName: string;
  readonly envName: string;
  readonly awsAccountId: string;
}

export function getConfig(): AppConfig {
  // Get the current directory path where the CDK file is located
  const currentDir = __dirname;

  // Construct the absolute path to the configuration file
  const configFilePath = path.join(
    currentDir,
    `../../config/prod-env.configuration.yaml`
  );

  // Read the YAML file and parse its contents
  const fileData = fs.readFileSync(configFilePath, "utf8");
  const parsedData: any = yaml.load(fileData);

  let config: AppConfig = {
    adminEmail: parsedData.adminEmail as string,
    appName: (process.env.APP_NAME as string) || "app",
    envName: (process.env.ENV_NAME as string) || "env",
    awsAccountId: Aws.ACCOUNT_ID as string,
  };

  return config;
}




