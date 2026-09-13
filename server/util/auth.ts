import type { UserDetails } from '@shared/api-response/UserDetails'
import { availableLoginFactors, isExpired, isUnapproved, isUnverifiedEmail, loginFactors, type amrFactor } from '@shared/user'
import { userRequiresMfa } from '../db/user'
import appConfig from './config'

function userMfaComplete(user: Pick<UserDetails, 'mfaRequired' | 'hasMfaGroup'>, amr: amrFactor[]) {
  const factors = loginFactors(amr)

  if (factors === 0) {
    return false
  }

  if (userRequiresMfa(user) && factors < 2) {
    return false
  }

  return true
}

function userCanMfa(user: UserDetails) {
  return loginFactors(availableLoginFactors(user)) > 1
}

/**
 * Determines if a user can login.
 * Checks that session has required factors, user is approved, and email is verified (if required)
 */
export function userCanLogin(
  user: Pick<UserDetails, 'mfaRequired' | 'hasMfaGroup' | 'hasTotp' | 'hasEmail' | 'emailVerified' | 'approved' | 'isAdmin'> | undefined,
  amr: amrFactor[],
): user is UserDetails {
  if (!user) {
    return false
  }

  if (!userMfaComplete(user, amr)) {
    return false
  }

  if (isUnapproved(user, appConfig.SIGNUP_REQUIRES_APPROVAL)) {
    return false
  }

  if (isExpired(user)) {
    return false
  }

  if (isUnverifiedEmail(user, !!appConfig.EMAIL_VERIFICATION)) {
    return false
  }

  return true
}

// A user is privileged for email actions with the same requirements as login
// but also allowing users without email to bypass verification requirement to set an email
export function userIsPrivilegedForEmail(user: UserDetails | undefined, amr: amrFactor[]): boolean {
  if (!user) {
    return false
  }

  if (!userMfaComplete(user, amr)) {
    return false
  }

  if (isUnapproved(user, appConfig.SIGNUP_REQUIRES_APPROVAL)) {
    return false
  }

  if (isExpired(user)) {
    return false
  }

  // A user that doesn't have an email can still manage their email, even if email verification is required
  if (user.hasEmail && isUnverifiedEmail(user, !!appConfig.EMAIL_VERIFICATION)) {
    return false
  }

  return true
}

export function userIsPrivilegedForTotpCreate(user: UserDetails | undefined, amr: amrFactor[]): boolean {
  if (!user) {
    return false
  }

  // If they already have mfa factors, require strict privilege to manage it. Otherwise allow set up
  if (userCanMfa(user) && !userMfaComplete(user, amr)) {
    return false
  }

  // Users can only create a totp if they are already at least partially logged in with a first factor
  if (!loginFactors(amr)) {
    return false
  }

  if (isUnapproved(user, appConfig.SIGNUP_REQUIRES_APPROVAL)) {
    return false
  }

  if (isExpired(user)) {
    return false
  }

  // Can still set up totp if they don't have an email, even if it is required
  if (user.hasEmail && isUnverifiedEmail(user, !!appConfig.EMAIL_VERIFICATION)) {
    return false
  }

  return true
}

export function userIsPrivilegedForPasskeyCreate(user: UserDetails | undefined, amr: amrFactor[]): boolean {
  return userIsPrivilegedForTotpCreate(user, amr)
}

export function userIsPrivilegedForTotpValidate(user: UserDetails | undefined, amr: amrFactor[]): boolean {
  return userIsPrivilegedForTotpCreate(user, amr)
}
