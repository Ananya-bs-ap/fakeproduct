/**
 * Frontend API Service
 * Communicates with full-stack Express API endpoints, with automatic client-side
 * risk engine fallback to ensure zero downtime.
 */

import {
  AssessmentResult,
  WebsiteAnalysisInput,
  ProductAnalysisInput,
  CodeAnalysisInput,
  MlPhishingResult,
} from '../types';
import { predictPhishing, getModelMetadata } from './mlInference';
import { RiskScoringEngine } from './riskEngine/engine';

export class ApiService {
  /**
   * Request ML Phishing Prediction (Uses model trained on Kaggle malicious_phish.csv)
   */
  public static async predictPhishingWithML(url: string): Promise<MlPhishingResult> {
    try {
      const response = await fetch('/api/ml/predict-phishing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (err: any) {
      console.warn('ML phishing server request error, running local inference:', err.message);
    }

    // Direct local inference using identical trained weights
    return predictPhishing(url);
  }

  /**
   * Get ML Model Training Information & Metrics
   */
  public static async getModelInfo() {
    try {
      const response = await fetch('/api/ml/model-info');
      if (response.ok) {
        return await response.json();
      }
    } catch {
      // Fallback to local metadata
    }
    return getModelMetadata();
  }
  /**
   * Analyze Website URL
   */
  public static async analyzeWebsite(input: WebsiteAnalysisInput): Promise<AssessmentResult> {
    try {
      const response = await fetch('/api/analyze/website', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });

      if (response.ok) {
        return await response.json();
      }
      const errData = await response.json().catch(() => ({}));
      if (errData.error) throw new Error(errData.error);
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    // Direct client engine fallback
    return RiskScoringEngine.assessWebsite(input);
  }

  /**
   * Analyze Product Listing
   */
  public static async analyzeProduct(input: ProductAnalysisInput): Promise<AssessmentResult> {
    try {
      const response = await fetch('/api/analyze/product', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });

      if (response.ok) {
        return await response.json();
      }
      const errData = await response.json().catch(() => ({}));
      if (errData.error) throw new Error(errData.error);
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    // Direct client engine fallback
    return RiskScoringEngine.assessProduct(input);
  }

  /**
   * Analyze Barcode / QR Code
   */
  public static async analyzeCode(input: CodeAnalysisInput): Promise<AssessmentResult> {
    try {
      const response = await fetch('/api/analyze/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });

      if (response.ok) {
        return await response.json();
      }
      const errData = await response.json().catch(() => ({}));
      if (errData.error) throw new Error(errData.error);
    } catch (err: any) {
      console.warn('Backend API request failed, using client engine fallback:', err.message);
    }

    // Direct client engine fallback
    return RiskScoringEngine.assessCode(input);
  }

  /**
   * Request AI Plain-Language Risk Explanation
   */
  public static async requestAiExplanation(result: AssessmentResult): Promise<{
    explanation: string;
    provider: 'gemini' | 'deterministic-fallback';
  }> {
    try {
      const response = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (err: any) {
      console.warn('AI explanation API error:', err.message);
    }

    return {
      explanation:
        'This assessment evaluates observable signals against known risk indicators. A low price or unknown domain requires diligence, but risk assessment is not physical proof of counterfeiting or fraud. Always verify returns and use secure payment methods.',
      provider: 'deterministic-fallback',
    };
  }
}
