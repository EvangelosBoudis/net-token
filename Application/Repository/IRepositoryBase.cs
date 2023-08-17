namespace Application.Repository;

public interface IRepositoryBase<in TEntity> where TEntity : class
{
    Task SaveAsync(TEntity entity);

    Task SaveAndFlushAsync(TEntity entity);
}