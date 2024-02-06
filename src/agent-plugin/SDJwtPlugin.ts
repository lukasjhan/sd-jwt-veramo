import { IAgentPlugin, IIdentifier, IKey } from '@veramo/core-types'
import {
  ISDJwtPlugin,
  IRequiredContext,
  ICreateVerifiableCredentialSDJwtArgs,
  ICreateVerifiableCredentialSDJwtResult,
  ICreateVerifiablePresentationSDJwtArgs,
  ICreateVerifiablePresentationSDJwtResult,
  IVerifyVerifiableCredentialSDJwtArgs,
  IVerifyVerifiableCredentialSDJwtResult,
  IVerifyVerifiablePresentationSDJwtArgs,
  IVerifyVerifiablePresentationSDJwtResult,
} from '../types/ISDJwtPlugin.js'
import { extractIssuer } from '@veramo/utils'
import { SDJwtInstance } from '@hopae/sd-jwt'
import crypto from 'node:crypto'

import schema from '../plugin.schema.json' assert { type: 'json' }

/**
 * {@inheritDoc ISDJwtPlugin}
 * @beta
 */
export class SDJwtPlugin implements IAgentPlugin {
  readonly schema = schema.ISDJwtPlugin

  // map the methods your plugin is declaring to their implementation
  readonly methods: ISDJwtPlugin = {
    createVerifiableCredentialSDJwt: this.createVerifiableCredentialSDJwt.bind(this),
    createVerifiablePresentationSDJwt: this.createVerifiablePresentationSDJwt.bind(this),
    verifyVerifiableCredentialSDJwt: this.verifyVerifiableCredentialSDJwt.bind(this),
    verifyVerifiablePresentationSDJwt: this.verifyVerifiablePresentationSDJwt.bind(this),
  }

  async createVerifiableCredentialSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiableCredentialSDJwtResult> {
    const { privateKey } = crypto.generateKeyPairSync('ed25519')

    const issuer = extractIssuer(args.credentialPayload, { removeParameters: true })
    if (!issuer) {
      throw new Error('invalid_argument: credential.issuer must not be empty')
    }
    /*
    const identifier = await context.agent.didManagerGet({ did: issuer })

    const { key, alg } = SDJwtPlugin.getSigningKey(identifier)

    const signer = context.agent.keyManagerGetSigner({ kid: key.kid, algorithm: alg })
*/
    const sdjwt = new SDJwtInstance()
    const credential = await sdjwt.issue(args.credentialPayload, privateKey)

    return { credential: credential }
  }

  async createVerifiablePresentationSDJwt(
    args: ICreateVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiablePresentationSDJwtResult> {
    const { privateKey } = crypto.generateKeyPairSync('ed25519')

    const sdjwt = new SDJwtInstance()
    const credential = await sdjwt.issue(args.presentation, privateKey)

    return { presentation: credential }
  }

  async verifyVerifiableCredentialSDJwt(
    args: IVerifyVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiableCredentialSDJwtResult> {
    const { publicKey } = crypto.generateKeyPairSync('ed25519')

    const sdjwt = new SDJwtInstance()
    const verifiedPayloads = await sdjwt.validate(args.credential, publicKey)

    return { verifiedPayloads }
  }

  async verifyVerifiablePresentationSDJwt(
    args: IVerifyVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiablePresentationSDJwtResult> {
    const { publicKey } = crypto.generateKeyPairSync('ed25519')

    const sdjwt = new SDJwtInstance()
    const verifiedPayloads = await sdjwt.validate(args.presentation, publicKey)

    return { verifiedPayloads }
  }

  private static getSigningKey(identifier: IIdentifier): { key: IKey; alg: string } {
    for (const key of identifier.keys) {
      if (key.type === 'Ed25519') {
        return { key, alg: 'EdDSA' }
      } else if (key.type === 'Secp256k1') {
        return { key, alg: 'ES256K' }
      } else if (key.type === 'Secp256r1') {
        return { key, alg: 'ES256' }
      }
    }

    throw Error(`key_not_found: No signing key for ${identifier.did}`)
  }
}
