import { Hasher, SaltGenerator } from '@sd-jwt/types';
import {
  CredentialPayload,
  IAgentContext,
  IDIDManager,
  IKeyManager,
  IPluginMethodMap,
  IResolver,
} from '@veramo/core-types';

/**
 * My Agent Plugin description.
 *
 * This is the interface that describes what your plugin can do.
 * The methods listed here, will be directly available to the veramo agent where your plugin is going to be used.
 * Depending on the agent configuration, other agent plugins, as well as the application where the agent is used
 * will be able to call these methods.
 *
 * To build a schema for your plugin using standard tools, you must link to this file in your package.json.
 * Example:
 * ```
 * "veramo": {
 *    "pluginInterfaces": {
 *      "IMyAgentPlugin": "./src/types/IMyAgentPlugin.ts"
 *    }
 *  },
 * ```
 *
 * @beta
 */
export interface ISDJwtPlugin extends IPluginMethodMap {
  /**
   * Your plugin method description
   *
   * @param args - Input parameters for this method
   * @param context - The required context where this method can run.
   *   Declaring a context type here lets other developers know which other plugins
   *   need to also be installed for this method to work.
   */
  /**
   * Create a signed SD-JWT credential.
   * @param args - Arguments necessary for the creation of a SD-JWT credential.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   */
  createVerifiableCredentialSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiableCredentialSDJwtResult>;

  /**
   * Create a signed SD-JWT presentation.
   * @param args - Arguments necessary for the creation of a SD-JWT presentation.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   */
  createVerifiablePresentationSDJwt(
    args: ICreateVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiablePresentationSDJwtResult>;

  /**
   * Verify a signed SD-JWT credential.
   * @param args - Arguments necessary for the verification of a SD-JWT credential.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   */
  verifyVerifiableCredentialSDJwt(
    args: IVerifyVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiableCredentialSDJwtResult>;

  /**
   * Verify a signed SD-JWT presentation.
   * @param args - Arguments necessary for the verification of a SD-JWT presentation.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   */
  verifyVerifiablePresentationSDJwt(
    args: IVerifyVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiablePresentationSDJwtResult>;
}

/**
 * ICreateVerifiableCredentialSDJwtArgs
 *
 * @beta
 */
export interface ICreateVerifiableCredentialSDJwtArgs {
  credentialPayload: CredentialPayload;

  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  disclosureFrame?: any;
}

/**
 * ICreateVerifiableCredentialSDJwtResult
 *
 * @beta
 */
export interface ICreateVerifiableCredentialSDJwtResult {
  credential: string;
}

/**
 * @beta
 */
export interface ICreateVerifiablePresentationSDJwtArgs {
  presentation: string;

  /*
   * The keys to use for selective disclosure for presentation
   * if not provided, all keys will be disclosed
   * if empty array, no keys will be disclosed
   */
  presentationKeys?: string[];
}

/**
 * @beta
 */
export interface ICreateVerifiablePresentationSDJwtResult {
  presentation: string;
}

/**
 * @beta
 */
export interface IVerifyVerifiableCredentialSDJwtArgs {
  credential: string;
}

/**
 * @beta
 */
export type IVerifyVerifiableCredentialSDJwtResult = {
  verifiedPayloads: unknown;
};

/**
 * @beta
 */
export interface IVerifyVerifiablePresentationSDJwtArgs {
  presentation: string;

  requiredClaimKeys?: string[];
}

/**
 * @beta
 */
export type IVerifyVerifiablePresentationSDJwtResult = {
  verifiedPayloads: unknown;
};

/**
 * This context describes the requirements of this plugin.
 * For this plugin to function properly, the agent needs to also have other plugins installed that implement the
 * interfaces declared here.
 * You can also define requirements on a more granular level, for each plugin method or event handler of your plugin.
 *
 * @beta
 */
export type IRequiredContext = IAgentContext<
  IDIDManager & IResolver & IKeyManager
>;
export interface SdJWTImplementation {
  salltGenerator: SaltGenerator;
  hasher: Hasher;
  verifySignature: (
    data: string,
    signature: string,
    publicKey: JsonWebKey
  ) => Promise<boolean>;
}
