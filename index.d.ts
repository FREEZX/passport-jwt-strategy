import * as express from 'express';

declare namespace JwtStrategy {
    interface StrategyStatic {
        new(options: StrategyOptions): StrategyInstance;
    }

    interface StrategyInstance {
        name: string;
        authenticate: (req: express.Request, options?: any) => void;
    }

    interface StrategyOptions {
		secret: string
		maxAge?: number
		algorithms?: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512';
		requestKey?: string;
		requestArg?: string;
	}
}

declare const JwtStrategy: JwtStrategy.StrategyStatic;
export = JwtStrategy;
