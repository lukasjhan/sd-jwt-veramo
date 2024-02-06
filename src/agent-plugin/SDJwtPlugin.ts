import { IAgentPlugin } from '@veramo/core-types'
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
    return { credential: 'foobar' }
  }

  async createVerifiablePresentationSDJwt(
    args: ICreateVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<ICreateVerifiablePresentationSDJwtResult> {
    return { presentation: 'foobar' }
  }

  async verifyVerifiableCredentialSDJwt(
    args: IVerifyVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiableCredentialSDJwtResult> {
    return { foobar: 'foobar' }
  }

  async verifyVerifiablePresentationSDJwt(
    args: IVerifyVerifiablePresentationSDJwtArgs,
    context: IRequiredContext
  ): Promise<IVerifyVerifiablePresentationSDJwtResult> {
    return { foobar: 'foobar' }
  }
}
