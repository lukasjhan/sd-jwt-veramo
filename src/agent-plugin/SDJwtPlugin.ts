import { Jwt, SDJwt, SDJwtInstance } from '@sd-jwt/core';
import { Signer, Verifier } from '@sd-jwt/types';
import { IAgentPlugin } from '@veramo/core-types';
import schema from '../plugin.schema.json' assert { type: 'json' };
import { SdJWTImplementation } from '../types/ISDJwtPlugin';
import {
  ICreateVerifiableCredentialSDJwtArgs,
  ICreateVerifiableCredentialSDJwtResult,
  ICreateVerifiablePresentationSDJwtArgs,
  ICreateVerifiablePresentationSDJwtResult,
  IRequiredContext,
  ISDJwtPlugin,
  IVerifyVerifiableCredentialSDJwtArgs,
  IVerifyVerifiableCredentialSDJwtResult,
  IVerifyVerifiablePresentationSDJwtArgs,
  IVerifyVerifiablePresentationSDJwtResult,
} from '../types/ISDJwtPlugin.js';
import { mapIdentifierKeysToDocWithJwkSupport } from '@sphereon/ssi-sdk-ext.did-utils';

interface Claims {
  id: string;
  [key: string]: unknown;
}

/**
 * SD-JWT plugin for Veramo
 */
export class SDJwtPlugin implements IAgentPlugin {
  readonly schema = schema.ISDJwtPlugin;

  constructor(private algorithms: SdJWTImplementation) {}

  // map the methods your plugin is declaring to their implementation
  readonly methods: ISDJwtPlugin = {
    createVerifiableCredentialSDJwt:
      this.createVerifiableCredentialSDJwt.bind(this),
    createVerifiablePresentationSDJwt:
      this.createVerifiablePresentationSDJwt.bind(this),
    verifyVerifiableCredentialSDJwt:
      this.verifyVerifiableCredentialSDJwt.bind(this),
    verifyVerifiablePresentationSDJwt:
      this.verifyVerifiablePresentationSDJwt.bind(this),
  };

  /**
   * Create a signed SD-JWT credential.
   * @param args - Arguments necessary for the creation of a SD-JWT credential.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   * @returns A signed SD-JWT credential.
   */
  async createVerifiableCredentialSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiableCredentialSDJwtResult> {
    const issuer = args.credentialPayload.iss;
    if (!issuer) {
      throw new Error('invalid_argument: credential.issuer must not be empty');
    }
    if (issuer.split('#').length === 1) {
      throw new Error(
        'invalid_argument: credential.issuer must contain a did id with key reference like did:exmaple.com#key-1'
      );
    }
    const { alg, key } = await this.getSignKey(issuer, context);

    //TODO: let the user also insert a method to sign the data
    const signer: Signer = async (data: string) =>
      context.agent.keyManagerSign({ keyRef: key.kid, data });

    const sdjwt = new SDJwtInstance({
      signer,
      hasher: this.algorithms.hasher,
      saltGenerator: this.algorithms.salltGenerator,
      signAlg: alg,
      hashAlg: 'SHA-256',
    });

    const credential = await sdjwt.issue(
      args.credentialPayload,
      args.disclosureFrame
    );
    return { credential };
  }

  private async getSignKey(issuer: string, context: IRequiredContext) {
    const identifier = await context.agent.didManagerGet({
      did: issuer.split('#')[0],
    });
    const doc = await mapIdentifierKeysToDocWithJwkSupport(
      identifier,
      'assertionMethod',
      context
    );
    if (!doc || doc.length === 0) throw new Error('No key found for signing');
    const key = doc[0];
    let alg: string;
    switch (key.type) {
      case 'Ed25519':
        alg = 'EdDSA';
        break;
      case 'Secp256k1':
        alg = 'ES256K';
        break;
      case 'Secp256r1':
        alg = 'ES256';
        break;
      default:
        throw new Error(`unsupported key type ${key.type}`);
    }
    return { alg, key };
  }

  /**
   * Create a signed SD-JWT presentation.
   * @param args - Arguments necessary for the creation of a SD-JWT presentation.
   * @param context - This reserved param is automatically added and handled by the framework, *do not override*
   * @returns A signed SD-JWT presentation.
   */
  async createVerifiablePresentationSDJwt(
    args: ICreateVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiablePresentationSDJwtResult> {
    const cred = await SDJwt.fromEncode(
      args.presentation,
      this.algorithms.hasher
    );
    const claims = await cred.getClaims<Claims>(this.algorithms.hasher);
    // get the holder id. In case of a w3c vc dm, it is in the credentialsubject
    const holderDID: string = claims.id;
    //get the key based on the credential
    if (!holderDID)
      throw new Error(
        'invalid_argument: credential does not include a holder reference'
      );
    const { alg, key } = await this.getSignKey(holderDID, context);

    const signer: Signer = async (data: string) => {
      return context.agent.keyManagerSign({ keyRef: key.kid, data });
    };

    const sdjwt = new SDJwtInstance({
      hasher: this.algorithms.hasher,
      saltGenerator: this.algorithms.salltGenerator,
      kbSigner: signer,
      kbSignAlg: alg,
    });
    const credential = await sdjwt.present(
      args.presentation,
      args.presentationKeys,
      { kb: args.kb }
    );
    return { presentation: credential };
  }

  /**
   * Verify a signed SD-JWT credential.
   * @param args
   * @param context
   * @returns
   */
  async verifyVerifiableCredentialSDJwt(
    args: IVerifyVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiableCredentialSDJwtResult> {
    // biome-ignore lint/style/useConst: <explanation>
    let sdjwt: SDJwtInstance;
    const verifier: Verifier = async (data: string, signature: string) =>
      this.verify(sdjwt, context, data, signature);

    sdjwt = new SDJwtInstance({ verifier, hasher: this.algorithms.hasher });
    const verifiedPayloads = await sdjwt.verify(args.credential);

    return { verifiedPayloads };
  }

  /**
   * Validates the signature of a SD-JWT
   * @param sdjwt
   * @param context
   * @param data
   * @param signature
   * @returns
   */
  async verify(
    sdjwt: SDJwtInstance,
    context: IRequiredContext,
    data: string,
    signature: string,
    verifyKb = false
  ) {
    const decodedVC = await sdjwt.decode(`${data}.${signature}`);
    const issuer: string = (
      (decodedVC.jwt as Jwt).payload as Record<string, unknown>
    ).iss as string;
    //check if the issuer is a did
    if (!issuer.startsWith('did:')) {
      throw new Error('invalid_issuer: issuer must be a did');
    }
    const didDoc = await context.agent.resolveDid({ didUrl: issuer });
    if (!didDoc) {
      throw new Error(
        'invalid_issuer: issuer did not resolve to a did document'
      );
    }
    const didDocumentKey = didDoc.didDocument?.verificationMethod?.find(
      (key) => key.id
    );
    if (!didDocumentKey) {
      throw new Error(
        'invalid_issuer: issuer did document does not include referenced key'
      );
    }
    //TODO: in case it's another did method, the value of the key can be also encoded as a base64url
    const key = didDocumentKey.publicKeyJwk as JsonWebKey;
    return this.algorithms.verifySignature(data, signature, key);
  }

  /**
   * Verify a signed SD-JWT presentation.
   * @param args
   * @param context
   * @returns
   */
  async verifyVerifiablePresentationSDJwt(
    args: IVerifyVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiablePresentationSDJwtResult> {
    // biome-ignore lint/style/useConst: <explanation>
    let sdjwt: SDJwtInstance;
    const verifier: Verifier = async (data: string, signature: string) =>
      this.verify(sdjwt, context, data, signature);
    const verifierKb: Verifier = async (data: string, signature: string) =>
      this.verify(sdjwt, context, data, signature, true);
    sdjwt = new SDJwtInstance({
      verifier,
      hasher: this.algorithms.hasher,
      kbVerifier: verifierKb,
    });
    const verifiedPayloads = await sdjwt.verify(
      args.presentation,
      args.requiredClaimKeys,
      args.kb
    );

    return { verifiedPayloads };
  }
}
