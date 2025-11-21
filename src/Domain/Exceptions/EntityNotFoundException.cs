namespace Domain.Exceptions;

public class EntityNotFoundException<T> : Exception where T : class
{
    public EntityNotFoundException(object identifier) : base(
        $"Entity: '{typeof(T).Name}' with ID: '{identifier}' not found.")
    {
    }

    public EntityNotFoundException() : base($"Entity: '{typeof(T).Name}' not found.")
    {
    }
}