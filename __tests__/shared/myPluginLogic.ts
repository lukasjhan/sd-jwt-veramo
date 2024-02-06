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

    it('Create Verifiable Credential SD JWT', async () => {
      const result = await agent.createVerifiableCredentialSDJwt({
        credentialPayload: {
          issuer: 'did:key:z6Mkkd7Nm1QcNuPWRRQwisH2ZycULqT9H2Q7wDUZSf57mK61',
          data: 'A',
        },
      })
      console.log({ result })
      expect(result).toBeDefined()
    })
  })
}
