import { body, validationResult } from "express-validator";

// Validation for Room Creation (POST)
export const validateRoomCreate = [
  body("roomNumber")
    .exists()
    .withMessage("Room number is required")
    .bail()
    .isString()
    .withMessage("Room number must be a string")
    .bail()
    .notEmpty()
    .withMessage("Room number cannot be empty"),
  body("type")
    .exists()
    .withMessage("Type is required")
    .bail()
    .isIn(["Twin", "Single"])
    .withMessage("Type must be Twin or Single"),
  body("floor").optional().isString(),
  body("window").optional().isBoolean(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

// Validation for Room Update (PATCH)
export const validateRoomUpdate = [
  body("roomNumber")
    .optional()
    .isString()
    .withMessage("Room number must be a string if provided")
    .bail()
    .notEmpty()
    .withMessage("Room number cannot be empty if provided"),
  body("type")
    .optional()
    .isIn(["Twin", "Single"])
    .withMessage("Type must be Twin or Single if provided"),
  body("floor").optional().isString(),
  body("window").optional().isBoolean(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

// Validation for User Update (PATCH) - remains unchanged except cleanup
export const validateUserUpdate = [
  body("firstName").optional().isString(),
  body("lastName").optional().isString(),
  body("email").optional().isEmail(),
  // Add further validations for onboarding.answers fields here if desired
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];
