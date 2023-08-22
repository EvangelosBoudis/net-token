namespace Domain.Exceptions;

public class EntityNotFoundException<T> : Exception where T : class
{
    public EntityNotFoundException(object? identifier = null) : base(
        $"Entity: '{typeof(T).Name}' with ID: '{identifier}' not found.")
    {
    }
}