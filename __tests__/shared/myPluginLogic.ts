// noinspection ES6PreferShortImport

import { TAgent, IMessageHandler } from '@veramo/core-types'
import { ISDJwtPlugin } from '../../src/types/ISDJwtPlugin.js'

type ConfiguredAgent = TAgent<ISDJwtPlugin & IMessageHandler>

export default (testContext: {
  getAgent: () => ConfiguredAgent
  setup: () => Promise<boolean>
  tearDown: () => Promise<boolean>
}) => {
  describe('my plugin', () => {
    let agent: ConfiguredAgent

    beforeAll(async () => {
      await testContext.setup()
      agent = testContext.getAgent()
    })
    afterAll(async () => {
      await testContext.tearDown()
    })

    it('should foo', async () => {
      const result = await agent.createVerifiableCredentialSDJwt({
        credentialPayload: {
          issuer: 'did:example:123',
        },
      })
      expect(result).toEqual({ credential: 'foobar' })
    })
  })
}
