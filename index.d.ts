import { Strategy } from "passport-strategy";

declare interface StrategyOptions {
	secret: string
	maxAge?: number
	algorithms?: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512';
	requestKey?: string;
	requestArg?: string;
}

declare class PassportJwtStrategy extends Strategy {
	constructor(StrategyOptions);
}