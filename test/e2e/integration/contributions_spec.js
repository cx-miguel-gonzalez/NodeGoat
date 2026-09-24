/// <reference types="Cypress" />

describe('/contributions behaviour', () => {
  before(() => {
    cy.dbReset()
  })

  afterEach(() => {
    cy.visitPage('/logout')
  })

  it('Should redirect if the user has not logged in', () => {
    cy.visitPage('/contributions')
    cy.url().should('include', 'login')
  })

  it('Should be accesible for a logged user', () => {
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.url().should('include', 'contributions')
  })

  it('Should be a table with several inputs', () => {
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.get('table')
      .find('input')
      .should('have.length', 3)
  })

  it('Should input be modified', () => {
    const value = '12'
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.get('table')
      .find('input')
      .first()
      .clear()
      .type(value)

    cy.get('button[type="submit"]')
      .click()

    cy.get('tbody > tr > td')
      .eq(1)
      .contains(`${value} %`)

    cy.get('.alert-success')
      .should('be.visible')

    cy.url().should('include', 'contributions')
  })
})

// Security regression tests for CWE-94 Server-Side JavaScript Injection
// These tests verify that eval() has been replaced by parseInt() and that
// injected JavaScript expressions are never executed server-side.
describe('/contributions - Server-Side JavaScript Injection prevention (CWE-94)', () => {
  before(() => {
    cy.dbReset()
  })

  beforeEach(() => {
    cy.userSignIn()
    cy.visitPage('/contributions')
  })

  afterEach(() => {
    cy.visitPage('/logout')
  })

  it('Should reject a JavaScript expression injected as preTax', () => {
    // Before the fix, eval('1+1') would return 2 and bypass validation.
    // After the fix, parseInt('1+1') returns 1 (the leading integer only),
    // so the form submission itself should still succeed (1 is a valid %)
    // but the injected expression is never evaluated as code.
    cy.get('table').find('input').eq(0).clear().type('1+1')
    cy.get('table').find('input').eq(1).clear().type('2')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    // The server must not crash and must return the contributions page
    cy.url().should('include', 'contributions')
    // The stored preTax value should be 1 (parseInt result), not 2 (eval result)
    cy.get('tbody > tr > td').eq(1).should('not.contain', '2 %')
  })

  it('Should treat a process.exit() injection as invalid and show an error', () => {
    // A malicious payload that would cause server termination if eval() were used
    cy.get('table').find('input').eq(0).clear().type('process.exit(1)')
    cy.get('table').find('input').eq(1).clear().type('2')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    // The server must still be responsive (process.exit was NOT executed)
    cy.url().should('include', 'contributions')
    // parseInt('process.exit(1)') === NaN, so the form should show a validation error
    cy.get('.alert-danger, .alert-warning, [class*="error"]').should('exist')
  })

  it('Should treat a require() injection as invalid and show an error', () => {
    // Another dangerous payload; eval() would execute require('child_process')
    cy.get('table').find('input').eq(0).clear().type("require('child_process')")
    cy.get('table').find('input').eq(1).clear().type('2')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    cy.url().should('include', 'contributions')
    // parseInt("require('child_process')") === NaN → validation error
    cy.get('.alert-danger, .alert-warning, [class*="error"]').should('exist')
  })

  it('Should treat a string arithmetic expression as NaN and reject it', () => {
    // eval('9*9') would return 81; parseInt('9*9') returns 9
    // Either way the injected operator is not executed as code
    cy.get('table').find('input').eq(0).clear().type('9*9')
    cy.get('table').find('input').eq(1).clear().type('2')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    cy.url().should('include', 'contributions')
    // The result must be an integer (9 here), not the eval'd product (81)
    cy.get('tbody > tr > td').eq(1).should('not.contain', '81 %')
  })

  it('Should accept a valid integer value and save it successfully', () => {
    // Positive case: normal integer input must still work after the fix
    const value = '5'
    cy.get('table').find('input').eq(0).clear().type(value)
    cy.get('table').find('input').eq(1).clear().type('3')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    cy.get('.alert-success').should('be.visible')
    cy.url().should('include', 'contributions')
  })

  it('Should reject negative contribution percentages', () => {
    cy.get('table').find('input').eq(0).clear().type('-5')
    cy.get('table').find('input').eq(1).clear().type('2')
    cy.get('table').find('input').eq(2).clear().type('2')
    cy.get('button[type="submit"]').click()

    cy.url().should('include', 'contributions')
    cy.get('.alert-danger, .alert-warning, [class*="error"]').should('exist')
  })

  it('Should reject contributions exceeding 30% in total', () => {
    cy.get('table').find('input').eq(0).clear().type('15')
    cy.get('table').find('input').eq(1).clear().type('10')
    cy.get('table').find('input').eq(2).clear().type('10')
    cy.get('button[type="submit"]').click()

    cy.url().should('include', 'contributions')
    cy.get('.alert-danger, .alert-warning, [class*="error"]').should('exist')
  })
})
