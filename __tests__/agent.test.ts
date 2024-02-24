import { subtle } from "node:crypto";
import { digest, generateSalt } from "@sd-jwt/crypto-nodejs";
import { DisclosureFrame } from "@sd-jwt/types";
import { createAgent } from "@veramo/core";
import {
	IDIDManager,
	IKeyManager,
	IResolver,
	TAgent,
} from "@veramo/core-types";
import {
	DIDStore,
	Entities,
	KeyStore,
	PrivateKeyStore,
	migrations,
} from "@veramo/data-store";
import { DIDManager } from "@veramo/did-manager";
import {
	JwkCreateIdentifierOptions,
	JwkDIDProvider,
	getDidJwkResolver,
} from "@veramo/did-provider-jwk";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import { KeyManager } from "@veramo/key-manager";
import { KeyManagementSystem, SecretBox } from "@veramo/kms-local";
import { Resolver } from "did-resolver";
import { createConnection } from "typeorm";
import { beforeAll, describe, expect, it } from "vitest";
import { ISDJwtPlugin, SDJwtPlugin } from "../src/";

async function verifySignature(
	data: string,
	signature: string,
	key: JsonWebKey,
) {
	let { alg, crv } = key;
	if (alg === "ES256") alg = "ECDSA";
	const publicKey = await subtle.importKey(
		"jwk",
		key,
		{ name: alg, namedCurve: crv } as EcKeyImportParams,
		true,
		["verify"],
	);
	return Promise.resolve(
		subtle.verify(
			{ name: alg!, hash: "SHA-256" },
			publicKey,
			Buffer.from(signature, "base64"),
			Buffer.from(data),
		),
	);
}

type AgentType = IDIDManager & IKeyManager & IResolver & ISDJwtPlugin;

describe("Agent plugin", () => {
	let agent: TAgent<AgentType>;

	let issuer: string;

	let holder: string;

	// Issuer Define the claims object with the user's information
	const claims = {
		sub: "john_deo_42",
		given_name: "John",
		family_name: "Deo",
		email: "johndeo@example.com",
		phone: "+1-202-555-0101",
		address: {
			street_address: "123 Main St",
			locality: "Anytown",
			region: "Anystate",
			country: "US",
		},
		birthdate: "1940-01-01",
	};

	// Issuer Define the disclosure frame to specify which claims can be disclosed
	const disclosureFrame: { credentialSubject: DisclosureFrame<typeof claims> } =
		{
			credentialSubject: {
				_sd: [
					"sub",
					"given_name",
					"family_name",
					"email",
					"phone",
					"address",
					"birthdate",
				],
			},
		};

	beforeAll(async () => {
		const KMS_SECRET_KEY = "000102030405060708090a0b0c0d0e0f";
		const dbConnection = await createConnection({
			type: "sqlite",
			database: ":memory:",
			entities: Entities,
			migrations,
			synchronize: true,
			logging: false,
		});
		agent = createAgent<AgentType>({
			plugins: [
				new SDJwtPlugin({
					hasher: digest,
					salltGenerator: generateSalt,
					verifySignature,
				}),
				new KeyManager({
					store: new KeyStore(dbConnection),
					kms: {
						local: new KeyManagementSystem(
							new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY)),
						),
					},
				}),
				new DIDResolverPlugin({
					resolver: new Resolver({
						...getDidJwkResolver(),
					}),
				}),
				new DIDManager({
					store: new DIDStore(dbConnection),
					defaultProvider: "did:jwk",
					providers: {
						"did:jwk": new JwkDIDProvider({
							defaultKms: "local",
						}),
					},
				}),
			],
		});
		issuer = await agent
			.didManagerCreate({
				kms: "local",
				provider: "did:jwk",
				alias: "issuer",
				//we use this curve since nodejs does not support ES256k which is the default one.
				options: { keyType: "Secp256r1" } as JwkCreateIdentifierOptions,
			})
			.then((did) => {
				// we add a key reference
				return `${did.did}#0`;
			});
		holder = await agent
			.didManagerCreate({
				kms: "local",
				provider: "did:jwk",
				alias: "holder",
				//we use this curve since nodejs does not support ES256k which is the default one.
				options: { keyType: "Secp256r1" } as JwkCreateIdentifierOptions,
			})
			.then((did) => {
				// we add a key reference
				return `${did.did}#0`;
			});
	});

	it("create a sd-jwt", async () => {
		const credential = await agent.createVerifiableCredentialSDJwt({
			credentialPayload: { credentialSubject: claims, issuer },
			disclosureFrame,
		});
		expect(credential).toBeDefined();
	});

	it("verify a sd-jwt", async () => {
		const credential = await agent.createVerifiableCredentialSDJwt({
			credentialPayload: { credentialSubject: claims, issuer },
			disclosureFrame: disclosureFrame,
		});
		const verified = await agent.verifyVerifiableCredentialSDJwt({
			credential: credential.credential,
		});
		console.log(JSON.stringify(verified, null, 4));
	}, 5000);

	it("create a presentation", async () => {
		const credential = await agent.createVerifiableCredentialSDJwt({
			credentialPayload: { credentialSubject: claims, issuer },
			disclosureFrame,
		});
		const presentation = await agent.createVerifiablePresentationSDJwt({
			presentation: credential.credential,
			presentationKeys: ["credentialSubject.given_name"],
		});
		expect(presentation).toBeDefined();
	});

	it("verify a presentation", async () => {
		const credential = await agent.createVerifiableCredentialSDJwt({
			credentialPayload: { credentialSubject: claims, issuer },
			disclosureFrame,
		});
		const presentation = await agent.createVerifiablePresentationSDJwt({
			presentation: credential.credential,
			presentationKeys: ["credentialSubject.given_name"],
		});
		const result = await agent.verifyVerifiablePresentationSDJwt({
			presentation: presentation.presentation,
			requiredClaimKeys: ["credentialSubject.given_name"],
		});
		expect(result).toBeDefined();
		expect(result.verifiedPayloads.payload.credentialSubject.given_name).toBe(
			"John",
		);
	});
});
