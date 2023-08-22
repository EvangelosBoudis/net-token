using System.Linq.Expressions;

namespace Application.Repository;

public interface ICrudRepository<TEntity, in TId> where TEntity : class
{
    Task<bool> ExistsByIdAsync(TId primaryKey);

    Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> expression);

    Task<TEntity> FindByIdAsync(TId primaryKey);

    Task<TEntity> FindAsync(Expression<Func<TEntity, bool>> expression);

    Task<IEnumerable<TEntity>> FindAllAsync();

    Task<IEnumerable<TEntity>> FindAllAsync(Expression<Func<TEntity, bool>> expression);

    Task SaveAsync(TEntity entity);

    Task SaveAllAsync(IEnumerable<TEntity> entities);

    void Delete(TEntity entity);

    void DeleteAll(IEnumerable<TEntity> entities);
}