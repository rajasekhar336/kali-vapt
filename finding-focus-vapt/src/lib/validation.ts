/**
 * Input Validation Schemas - VAPT Platform
 * 
 * Centralized validation schemas using Zod for all user inputs.
 * This provides client-side validation with the same schemas
 * that should be enforced server-side in the Laravel backend.
 */

import { z } from 'zod';

// Domain name validation - follows RFC 1035 with common restrictions
export const domainNameSchema = z
  .string()
  .min(1, 'Domain name is required')
  .max(253, 'Domain name is too long')
  .regex(
    /^(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,}$/,
    'Invalid domain name format (e.g., example.com)'
  )
  .transform((val) => val.toLowerCase().trim());

// Username validation - relaxed for mock, Laravel backend enforces stricter rules
export const usernameSchema = z
  .string()
  .min(1, 'Username is required')
  .max(100, 'Username is too long')
  .transform((val) => val.trim());

// Password validation - relaxed for mock, Laravel backend enforces stricter rules
export const passwordSchema = z
  .string()
  .min(1, 'Password is required')
  .max(128, 'Password is too long');

// Login credentials schema
export const loginCredentialsSchema = z.object({
  username: usernameSchema,
  password: passwordSchema,
});

// Finding notes validation
export const findingNotesSchema = z
  .string()
  .max(5000, 'Notes cannot exceed 5000 characters')
  .transform((val) => val.trim());

// Validation status
export const validationStatusSchema = z.enum([
  'pending',
  'validated',
  'false_positive',
  'needs_review',
]);

// Risk status
export const riskStatusSchema = z.enum([
  'open',
  'mitigated',
  'accepted',
]);

// Domain creation request
export const createDomainRequestSchema = z.object({
  domainName: domainNameSchema,
});

// Batch validation request
export const batchValidationRequestSchema = z.object({
  findingIds: z.array(z.string().min(1)).min(1, 'At least one finding must be selected'),
  status: validationStatusSchema,
});

// Result types for validation
export type ValidationSuccess<T> = { success: true; data: T };
export type ValidationFailure = { success: false; errors: string[] };
export type ValidationResult<T> = ValidationSuccess<T> | ValidationFailure;

// Helper function to safely validate input and return result
export function validateInput<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): ValidationResult<T> {
  const result = schema.safeParse(data);
  
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  return {
    success: false,
    errors: result.error.errors.map((e) => e.message),
  };
}

// Export types inferred from schemas
export type LoginCredentials = z.infer<typeof loginCredentialsSchema>;
export type CreateDomainRequest = z.infer<typeof createDomainRequestSchema>;
export type ValidationStatusInput = z.infer<typeof validationStatusSchema>;
export type RiskStatusInput = z.infer<typeof riskStatusSchema>;
