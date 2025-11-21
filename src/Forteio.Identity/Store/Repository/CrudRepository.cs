using System.Linq.Expressions;
using Application.Store.Repository;
using Domain.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace Forteio.Identity.Store.Repository;

public class CrudRepository<TEntity, TId> : ICrudRepository<TEntity, TId> where TEntity : class
{
    protected readonly DbContext Context;

    protected CrudRepository(DbContext context)
    {
        Context = context;
    }

    public async Task<bool> ExistsByIdAsync(TId primaryKey)
    {
        var entity = await Context
            .Set<TEntity>()
            .FindAsync(primaryKey);

        return entity is not null;
    }

    public async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> expression)
    {
        var count = await Context
            .Set<TEntity>()
            .Where(expression)
            .CountAsync();

        return count > 0;
    }

    public async Task<TEntity> FindByIdAsync(TId primaryKey)
    {
        var entity = await Context
            .Set<TEntity>()
            .FindAsync(primaryKey);

        if (entity is not null) return entity;
        throw new EntityNotFoundException<TEntity>(primaryKey);
    }

    public async Task<TEntity> FindAsync(Expression<Func<TEntity, bool>> expression)
    {
        var entity = await Context
            .Set<TEntity>()
            .Where(expression)
            .FirstOrDefaultAsync();

        if (entity is not null) return entity;
        throw new EntityNotFoundException<TEntity>();
    }

    public async Task<IEnumerable<TEntity>> FindAllAsync()
    {
        return await Context
            .Set<TEntity>()
            .ToListAsync();
    }

    public async Task<IEnumerable<TEntity>> FindAllAsync(Expression<Func<TEntity, bool>> expression)
    {
        return await Context
            .Set<TEntity>()
            .Where(expression)
            .ToListAsync();
    }

    public async Task SaveAsync(TEntity entity)
    {
        await Context
            .Set<TEntity>()
            .AddAsync(entity);
    }

    public async Task SaveAllAsync(IEnumerable<TEntity> entities)
    {
        await Context
            .Set<TEntity>()
            .AddRangeAsync(entities);
    }

    public void Delete(TEntity entity)
    {
        Context
            .Set<TEntity>()
            .Remove(entity);
    }

    public void DeleteAll(IEnumerable<TEntity> entities)
    {
        Context
            .Set<TEntity>()
            .RemoveRange(entities);
    }
}