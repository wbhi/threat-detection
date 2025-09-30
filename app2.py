import pickle

# Load your saved model
with open("LinearSVCTuned.pkl", "rb") as f:
    model = pickle.load(f)

# Print the model object type
print(type(model))

# Print model parameters
print("Model Parameters:")
print(model.get_params())

# Print the classes the model can predict
print("\nClasses:")
print(model.classes_)

# Print the learned coefficients (weights)
print("\nCoefficients shape:", model.coef_.shape)
print("Coefficients:")
print(model.coef_)

# Print the intercept (bias terms)
print("\nIntercept:")
print(model.intercept_)
